"""Phase 6 LIVE verification. Run from the backend folder with .env filled in (VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY):

    python -m scripts.verify_threat_intel

Calls the REAL feeds with well-known indicators (the EICAR test-file hash, 8.8.8.8, example.com). No mocks. Each check is
PASS, FAIL or SKIP (feed has no key). Exit code 1 if anything FAILED. Uses ~6 lookups: mind the VirusTotal public quota."""
import asyncio
import sys

from app.services import ti_providers as tp

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
fails = 0


def rec(status, name, detail=""):
    global fails
    fails += status == "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))


async def main() -> int:
    for p, ok in tp.status().items():
        if not ok["configured"]:
            rec("SKIP", p, "no API key configured")
    for kind, val in (("sha256", EICAR), ("ip", "8.8.8.8"), ("domain", "example.com")):
        res = await tp.lookup(kind, val)
        for p, r in res.items():
            if r["status"] == "unavailable":
                continue
            rec("PASS" if r["status"] in ("ok", "not_found") else "FAIL", f"{p} {kind}", f"status={r['status']} {r['summary'] if r['status'] != 'ok' else ''}".strip())
        vt = res.get("virustotal")
        if kind == "sha256" and vt and vt["status"] == "ok":
            rec("PASS" if vt["summary"]["malicious"] > 10 else "FAIL", "VirusTotal flags EICAR as malicious", f"malicious={vt['summary']['malicious']}")
    return 1 if fails else 0


sys.exit(asyncio.run(main()))
