"""Adapter around the two EXISTING CrewAI projects under agents/ (not modified, not re-implemented).

SOC agent  : imports AiSocCopilotWazuhInvestigatorCrew and kicks it off (its read-only Wazuh tool does the queries).
Email agent: reads the Harbor flow.json and reuses its `identify_department` and `assess_sensitivity` steps
             (role/goal/backstory/prompt/expected output) verbatim. Its Gmail fetch/forward steps need CrewAI-platform
             Gmail connectors, so the email text comes from the API caller and forwarding is NEVER performed here:
             routing is returned as a recommendation computed deterministically from the flow's own recipient directory.
Nothing is ever fabricated: if an agent can't run or its output can't be parsed, the caller gets an error/None.
"""
import asyncio
import importlib
import importlib.util
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import get_settings
from app.core.errors import UpstreamError
from app.services import secret_vault

log = logging.getLogger("freightshield.ai")
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_sem: asyncio.Semaphore | None = None


class AgentUnavailable(Exception):
    """Agent cannot run (missing dependency, key, path or Wazuh config). Mapped to HTTP 503."""

    def __init__(self, agent: str, reasons: list[str]):
        self.agent, self.reasons = agent, reasons
        super().__init__(f"{agent} unavailable: {'; '.join(reasons)}")


def _path(p: str) -> Path:
    q = Path(p)
    return q if q.is_absolute() else _BACKEND_ROOT / q


def _soc_src() -> Path:
    return _path(get_settings().ai_soc_agent_path) / "src"


def _flow_file() -> Path:
    return next((_path(get_settings().ai_email_agent_path) / "src").glob("*/flow.json"), Path("missing-flow.json"))


# ---------------------------------------------------------------- status
def _vault_configured(name: str) -> bool:
    try:
        return any(x["name"] == name and (x["stored_encrypted"] or x["environment_fallback"])
                   for x in secret_vault.inventory())
    except Exception:
        return False


def _load_provider_secrets() -> None:
    # Secrets are decrypted only inside the backend process immediately before the agent runs.
    for name in ("OPENAI_API_KEY", "EXA_API_KEY"):
        value = secret_vault.get(name)
        if value:
            os.environ[name] = value


def status() -> dict:
    """Honest readiness per agent. 'ready' only when every prerequisite is present; nothing is probed live."""
    s = get_settings()
    crewai = importlib.util.find_spec("crewai") is not None
    common = ([] if crewai else ["crewai is not installed (pip install -r requirements-ai.txt)"]) + \
             ([] if (os.getenv("OPENAI_API_KEY") or _vault_configured("OPENAI_API_KEY")) else ["OPENAI_API_KEY is not set"])
    soc = list(common)
    if not (_soc_src().is_dir() and any(_soc_src().glob("*/crew.py"))):
        soc.append("SOC agent project not found")
    if not (os.getenv("EXA_API_KEY") or _vault_configured("EXA_API_KEY")):
        soc.append("EXA_API_KEY is not set (threat analyzer tool)")
    if not (s.wazuh_manager_url and s.wazuh_manager_user and s.wazuh_manager_password):
        soc.append("Wazuh Manager is not configured")
    if not (s.wazuh_indexer_url and s.wazuh_indexer_user and s.wazuh_indexer_password):
        soc.append("Wazuh Indexer is not configured")
    email = list(common)
    if not _flow_file().is_file():
        email.append("Email agent flow.json not found")

    def one(name, reasons):
        return {"agent": name, "state": "ready" if not reasons else "unavailable", "reasons": reasons}
    return {"soc": one("Wazuh SOC Investigator", soc), "email": one("Harbor Email Router", email),
            "email_forwarding": "disabled (recommendation only; nothing is sent)"}


# ---------------------------------------------------------------- SOC agent
def _wazuh_env() -> None:
    """Map the backend's Wazuh settings onto the env names the agent's own tool reads (single source of truth)."""
    s = get_settings()
    os.environ.update({"WAZUH_API_URL": s.wazuh_manager_url, "WAZUH_API_USERNAME": s.wazuh_manager_user,
                       "WAZUH_API_KEY": s.wazuh_manager_password, "WAZUH_INDEXER_URL": s.wazuh_indexer_url,
                       "WAZUH_INDEXER_USERNAME": s.wazuh_indexer_user, "WAZUH_INDEXER_KEY": s.wazuh_indexer_password,
                       "WAZUH_VERIFY_SSL": "true" if s.wazuh_verify_ssl else "false"})


def _run_soc_sync(request: str, time_range: str) -> dict:
    _wazuh_env()
    src = str(_soc_src())
    if src not in sys.path:
        sys.path.insert(0, src)
    mod = importlib.import_module("ai_soc_copilot___wazuh_investigator.crew")
    result = mod.AiSocCopilotWazuhInvestigatorCrew().crew().kickoff(
        inputs={"investigation_request": request, "time_range": time_range})
    tasks = [{"task": getattr(t, "name", None) or f"task_{i + 1}", "output": getattr(t, "raw", str(t))}
             for i, t in enumerate(getattr(result, "tasks_output", None) or [])]
    return {"report": getattr(result, "raw", None) or str(result), "tasks": tasks}


# ---------------------------------------------------------------- Email agent (flow.json reuse)
def _flow() -> dict:
    return json.loads(_flow_file().read_text(encoding="utf-8"))


def _step(flow: dict, name: str) -> dict:
    return flow["methods"][name]["do"]["with"]


def _dir_lines(flow: dict) -> dict[str, str]:
    """Recipient directory exactly as written in the flow's forward step: {label: address}."""
    txt = _step(flow, "forward_email")["input"]
    return {m.group(1).strip(): m.group(2) for m in re.finditer(r"^- (.+?): (\S+@\S+)$", txt, re.M)}


def _departments(flow: dict) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"^\d\. (.+?) \(", _step(flow, "identify_department")["input"], re.M)]


def _agent_run(step: dict, slot_value: str) -> str:
    """Run one flow step verbatim: its prompt with the ${outputs.*.raw} slot filled, its 'Expected output:' tail as the
    task's expected output. (flow.json embeds both in the single `input` string.)"""
    from crewai import LLM, Agent, Crew, Process, Task
    prompt = re.sub(r"\$\{outputs\.\w+\.raw\}", lambda _: slot_value, step["input"])
    expected = prompt.split("Expected output:", 1)[1].strip() if "Expected output:" in prompt else "As instructed."
    a = Agent(role=step["role"], goal=step["goal"], backstory=step["backstory"], llm=LLM(model=step["llm"]),
              inject_date=True, allow_delegation=False, verbose=False)
    t = Task(description=prompt, expected_output=expected, agent=a)
    out = Crew(agents=[a], tasks=[t], process=Process.sequential, verbose=False).kickoff()
    return getattr(out, "raw", None) or str(out)


def _clean(v: str, n: int) -> str:
    return re.sub(r"[\r\n]+", " ", v or "").strip()[:n]


def build_email_block(msg: dict) -> str:
    """Same block layout the flow's fetch step produces, built from caller-supplied (untrusted) email text."""
    return (f"Message ID: {_clean(msg.get('message_id') or 'n/a', 200)}\nThread ID: n/a\nFrom: {_clean(msg['from_address'], 320)}\n"
            f"To: {_clean(msg.get('to') or 'n/a', 500)}\nCc: n/a\nDate: {_clean(msg.get('date') or 'n/a', 100)}\n"
            f"Subject: {_clean(msg['subject'], 500)}\nAttachments: {_clean(', '.join(msg.get('attachments') or []) or 'none', 500)}\n"
            f"Body:\n{msg['body'][:20000]}")


def _run_email_sync(msg: dict) -> dict:
    flow = _flow()
    block = build_email_block(msg)
    dep_step, sens_step = _step(flow, "identify_department"), _step(flow, "assess_sensitivity")
    dep_raw = _agent_run(dep_step, block)
    sens_raw = _agent_run(sens_step, dep_raw)
    return {"department_raw": dep_raw, "sensitivity_raw": sens_raw, "flow": flow}


def _last(label: str, text: str) -> str | None:
    """LAST match: the agent echoes the email first, so an attacker-written 'Department:' line in the body can't win."""
    m = re.findall(rf"^{label}:\s*(.+)$", text, re.M | re.I)
    return m[-1].strip() if m else None


_SEC_RE = re.compile(r"phish|breach|malware|ransomware|compromis|credential|unauthori[sz]ed access|cyber|suspicious", re.I)


def interpret(raw: dict) -> dict:
    """Parse agent output + compute the routing recommendation. Unparseable fields stay None (never guessed)."""
    flow, text = raw["flow"], raw["sensitivity_raw"]
    depts = _departments(flow)
    dept = _last("Department", text)
    dept = next((d for d in depts if dept and d.lower() == dept.lower()), None)
    sens = (_last("Sensitivity", text) or "").lower()
    sens = sens if sens in ("high", "medium", "low") else None
    dreason, sreason = _last("Department reason", text), _last("Sensitivity reason", text)
    out = {"department": dept, "sensitivity": sens, "department_reason": dreason, "sensitivity_reason": sreason,
           "escalate_to_it_security": False, "recommended_recipients": [], "skipped_roles": [],
           "forwarded": False, "parsed": bool(dept and sens), "raw_output": text}
    if not out["parsed"]:
        return out
    directory = _dir_lines(flow)
    key = {"IT": "IT & Information Security", "Acc": "Accounting & Finance", "Dis": "Dispatch & Logistics",
           "Pro": "Procurement / Vendor", "Aud": "Internal Audit & Compliance"}
    pref = next((v for v in key.values() if dept.startswith(v)), None)
    mgr = [l for l in directory if pref and l.startswith(pref) and "Manager" in l and "Chair" not in l]
    staff = [l for l in directory if (pref and l.startswith(pref) and "staff" in l) or (not pref and l.startswith("Executive Leadership office"))]
    leaders = [l for l in directory if re.search(r"\b(CEO|MD|GM)\b", l)]
    security = [l for l in directory if l.startswith(("IT Security Administrators", "Security Professionals"))]
    if sens == "high":
        wanted = leaders + [l for l in directory if l.endswith("Manager")]
    elif sens == "medium":
        wanted = mgr + security + [l for l in leaders if "(GM)" in l]
    else:
        wanted = staff
    esc = dept.startswith("IT & Information Security") or bool(_SEC_RE.search(f"{dreason or ''} {sreason or ''}"))
    if esc:  # security-related mail always reaches IT Security, whatever its sensitivity level
        wanted = wanted + security
    seen, rec = set(), []
    for l in wanted:
        if l in directory and directory[l] not in seen:
            seen.add(directory[l]); rec.append({"role": l, "address": directory[l]})
    out.update(escalate_to_it_security=esc, recommended_recipients=rec,
               skipped_roles=[] if rec else ["no directory address matched the chosen roles"])
    return out


# ---------------------------------------------------------------- async entry points
async def _guarded(agent: str, reasons: list[str], fn, *args) -> dict:
    global _sem
    if reasons:
        raise AgentUnavailable(agent, reasons)
    s = get_settings()
    _sem = _sem or asyncio.Semaphore(max(1, s.ai_max_concurrent))
    t0 = time.monotonic()
    async with _sem:
        try:
            res = await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=s.ai_timeout_seconds)
        except asyncio.TimeoutError as e:
            log.warning("%s timed out after %ss", agent, s.ai_timeout_seconds)
            raise UpstreamError(agent, "The AI agent timed out.", 504) from e
        except ImportError as e:
            raise AgentUnavailable(agent, [f"agent dependency import failed: {type(e).__name__}"]) from e
        except Exception as e:  # message may carry upstream details; log the class only, return a generic error
            log.error("%s failed: %s", agent, type(e).__name__)
            raise UpstreamError(agent, f"The AI agent failed ({type(e).__name__}).", 502) from e
    res["duration_ms"] = int((time.monotonic() - t0) * 1000)
    res["generated_at"] = datetime.now(timezone.utc).isoformat()
    return res


async def run_soc(request: str, time_range: str) -> dict:
    return await _guarded("soc_agent", status()["soc"]["reasons"], _run_soc_sync, request, time_range)


async def run_email(msg: dict) -> dict:
    raw = await _guarded("email_agent", status()["email"]["reasons"], _run_email_sync, msg)
    meta = {k: raw[k] for k in ("duration_ms", "generated_at")}
    return {**interpret(raw), **meta}
