"""Phase 2 LIVE verification. Run from the backend folder with the backend running and .env filled in:

    python -m scripts.verify_integration [--base http://localhost:8000/api] [--google-credential <real Google ID token>]

Nothing is mocked: it calls your running API, which calls your real Wazuh Manager/Indexer and Google's key endpoint.
It reads users from the SQLite DB to mint session JWTs with AUTH_JWT_SECRET (use a test DB / non-prod secret).
Each check is PASS, FAIL or SKIP (could not be checked, with the reason). Exit code 1 if anything FAILED.
"""
import argparse
import sys
import time

import httpx
import jwt

from app.core.config import get_settings
from app.core.security import issue_token
from app.services import google_auth, users

results: list[tuple[str, str, str]] = []


def rec(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))


def check(name: str, ok: bool, detail: str = "") -> None:
    rec("PASS" if ok else "FAIL", name, detail)


def first_user(role: str):
    items, _ = users.list_users(1, 0, role, True)
    return items[0] if items else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000/api")
    ap.add_argument("--google-credential", help="a REAL Google ID token (from the browser sign-in) to test /auth/google")
    a = ap.parse_args()
    s = get_settings()
    http = httpx.Client(base_url=a.base, timeout=30)
    bearer = lambda t: {"Authorization": f"Bearer {t}"}

    # --- backend + configuration -------------------------------------------------------------------------
    try:
        h = http.get("/health")
    except httpx.HTTPError as e:
        rec("FAIL", "backend reachable", f"{type(e).__name__}: is it running at {a.base}?")
        return 1
    check("backend /health", h.status_code == 200, f"HTTP {h.status_code}")
    st = http.get("/auth/status").json()
    check("JWT secret configured (>=32 chars)", st.get("jwt_configured") is True)
    check("GOOGLE_CLIENT_ID configured", st.get("google_configured") is True)

    # --- Google OAuth ------------------------------------------------------------------------------------
    try:
        keys = httpx.get(google_auth.JWKS_URL, timeout=15).json().get("keys", [])
        check("Google signing keys reachable (live)", len(keys) > 0, f"{len(keys)} keys")
    except Exception as e:
        rec("FAIL", "Google signing keys reachable (live)", type(e).__name__)
    if a.google_credential:
        r = http.post("/auth/google", json={"credential": a.google_credential})
        check("Google ID token -> session", r.status_code == 200 and "set-cookie" in r.headers,
              f"HTTP {r.status_code} {r.json().get('detail', r.json().get('role', ''))}")
        if r.status_code == 200:
            me = http.get("/auth/me", headers={"Cookie": r.headers["set-cookie"].split(";")[0]})
            check("session cookie accepted by /auth/me", me.status_code == 200, me.text[:120])
    else:
        rec("SKIP", "interactive Google login", "pass --google-credential with a real ID token to test it")
    check("forged Google credential rejected", http.post("/auth/google", json={"credential": "a" * 40}).status_code == 401)

    # --- JWT issuance / validation / authorization ------------------------------------------------------
    admin = first_user("admin")
    if not admin:
        rec("FAIL", "an active admin exists in the DB", "run: python -m app.cli create-admin you@example.com")
        return 1
    tok = issue_token(admin, s)
    me = http.get("/auth/me", headers=bearer(tok))
    check("valid JWT accepted", me.status_code == 200 and me.json().get("role") == "admin", f"HTTP {me.status_code}")
    check("no token -> 401", http.get("/auth/me").status_code == 401)
    check("tampered JWT -> 401", http.get("/auth/me", headers=bearer(tok[:-3] + "AAA")).status_code == 401)
    wrong = jwt.encode({"sub": str(admin["id"]), "exp": int(time.time()) + 60}, "x" * 40, algorithm="HS256")
    check("JWT signed with wrong secret -> 401", http.get("/auth/me", headers=bearer(wrong)).status_code == 401)
    old = jwt.encode({"sub": str(admin["id"]), "exp": int(time.time()) - 60}, s.auth_jwt_secret, algorithm="HS256")
    check("expired JWT -> 401", http.get("/auth/me", headers=bearer(old)).status_code == 401)
    for role, denied in (("user", "/wazuh/manager/agents"), ("vendor", "/wazuh/indexer/alerts")):
        u = first_user(role)
        if u:
            check(f"{role} role denied {denied}", http.get(denied, headers=bearer(issue_token(u, s))).status_code == 403)
        else:
            rec("SKIP", f"{role} authorization", f"no active {role} user in the DB")
    v = first_user("vendor")
    if v:
        r = http.get("/vendor/agents", headers=bearer(issue_token(v, s)))
        check("vendor /vendor/agents (live, scoped)", r.status_code == 200, f"HTTP {r.status_code}"
              f" agents={[x['id'] for x in r.json().get('data', {}).get('affected_items', [])] if r.status_code == 200 else r.text[:100]}")

    # --- Wazuh (through the API, as an admin) -----------------------------------------------------------
    A = bearer(tok)
    for name, path in (("Wazuh Manager info", "/wazuh/manager/info"), ("Wazuh Indexer health", "/wazuh/indexer/health")):
        r = http.get(path, headers=A)
        d = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        check(name + " (live)", r.status_code == 200, f"HTTP {r.status_code} " + (str(d.get("error") or d.get("detail") or "")
              if r.status_code != 200 else str(d.get("data", {}).get("api_version") or d.get("status"))))
    r = http.get("/wazuh/manager/agents", headers=A)
    if r.status_code == 200:
        items = r.json().get("data", {}).get("affected_items", [])
        by = {}
        for x in items:
            by[x.get("status")] = by.get(x.get("status"), 0) + 1
        check("live agent retrieval", True, f"{len(items)} agents {by}")
        if not items:
            rec("SKIP", "agent field check", "Wazuh reports zero agents")
    else:
        rec("FAIL", "live agent retrieval", f"HTTP {r.status_code} {r.text[:150]}")
    r = http.get("/wazuh/indexer/alerts?limit=5", headers=A)
    if r.status_code == 200:
        d = r.json()
        hits = d.get("hits", {}).get("hits", [])
        check("live alert retrieval", "pagination" in d, f"total={d['hits']['total']['value']} returned={len(hits)}"
              + (f" newest={hits[0]['_source'].get('timestamp')}" if hits else ""))
        if not hits:
            rec("SKIP", "alert field check", "no alerts in wazuh-alerts-* (a genuine empty result, not a failure)")
    else:
        rec("FAIL", "live alert retrieval", f"HTTP {r.status_code} {r.text[:150]}")

    # --- error handling ---------------------------------------------------------------------------------
    check("invalid limit -> 422", http.get("/wazuh/indexer/alerts?limit=0", headers=A).status_code == 422)
    check("result window exceeded -> 422", http.get("/wazuh/indexer/alerts?limit=100&page=101", headers=A).status_code == 422)
    check("unknown agent status -> 422", http.get("/wazuh/manager/agents?status=bogus", headers=A).status_code == 422)
    check("audit log readable by admin", http.get("/audit/logs?limit=1", headers=A).status_code == 200)

    # --- Phase 3: detection on REAL Wazuh data (no synthetic events are ever injected by this script) -----
    r = http.post("/detections/run", headers=A)
    if r.status_code == 200:
        d = r.json()
        check("live detection scan", True, f"events_read={d['events']} lookback={d['lookback_seconds']}s created={len(d['created'])} "
              f"updated={len(d['updated'])} truncated={d['truncated']}")
        if d["events"] == 0:
            rec("SKIP", "detection logic on live data", "no Wazuh alerts in the lookback window; generate real events (e.g. 6 failed SSH logins) and rerun")
        again = http.post("/detections/run", headers=A).json()
        check("live rescan creates no duplicates", again.get("created") == [], f"created={again.get('created')}")
        al = http.get("/detections/alerts?limit=3", headers=A).json()
        print("   sample live alerts:", [(x["id"], x["rule_key"], x["severity"], x["status"], x["agent_id"], [m["id"] for m in x["mitre"]]) for x in al["items"]] or "none triggered")
        check("summary + notifications endpoints", http.get("/detections/summary", headers=A).status_code == 200
              and http.get("/notifications", headers=A).status_code == 200)
    else:
        rec("FAIL", "live detection scan", f"HTTP {r.status_code} {r.text[:150]}")
    check("detection rules readable", http.get("/detections/rules", headers=A).status_code == 200)
    v = first_user("vendor")
    if v:
        r = http.get("/vendor/detections/alerts", headers=bearer(issue_token(v, s)))
        ids = {x["agent_id"] for x in r.json().get("items", [])} if r.status_code == 200 else set()
        from app.services import vendor_agents
        check("vendor detections scoped to assigned agents", r.status_code == 200 and ids <= set(vendor_agents.agent_ids(v["id"])), f"agents_seen={sorted(ids)}")

    # --- Phase 9: threat hunting on REAL Wazuh data ----------------------------------------------------------
    r = http.get("/hunting/analysis?hours=24", headers=A)
    if r.status_code == 200:
        d = r.json()
        check("live hunting analysis", "mitre" in d and "behaviours" in d,
              f"events={d['total_events']} analysed={d['analyzed_events']} behaviours={len(d['behaviours'])} chains={len(d['correlations'])} tactics={len(d['mitre'])}")
        if not d["total_events"]:
            rec("SKIP", "hunting on live events", "no Wazuh alerts in the last 24 h (a genuine empty result)")
        e = http.get("/hunting/events?hours=24&limit=5", headers=A)
        check("live hunting events", e.status_code == 200 and e.json()["total"] == d["total_events"], f"HTTP {e.status_code}")
    else:
        rec("FAIL", "live hunting analysis", f"HTTP {r.status_code} {r.text[:150]}")
    check("hunting denied to anonymous", http.get("/hunting/events").status_code == 401)
    if v:
        from app.services import vendor_agents
        r = http.get("/vendor/hunting/events?hours=24&limit=100", headers=bearer(issue_token(v, s)))
        seen = {x["agent_id"] for x in r.json().get("items", [])} if r.status_code == 200 else set()
        check("vendor hunting scoped to assigned agents", r.status_code == 200 and seen <= set(vendor_agents.agent_ids(v["id"])), f"agents_seen={sorted(seen)}")
        check("vendor denied admin hunting", http.get("/hunting/events", headers=bearer(issue_token(v, s))).status_code == 403)

    n = {k: sum(1 for x in results if x[0] == k) for k in ("PASS", "FAIL", "SKIP")}
    print(f"\nSummary: {n['PASS']} passed, {n['FAIL']} failed, {n['SKIP']} skipped")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
