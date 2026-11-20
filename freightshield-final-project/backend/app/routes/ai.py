"""AI endpoints (admin-only via the `ai:use` permission). Vendors and plain users get 403 from the guard, so vendor
isolation is preserved: the agents query Wazuh with the server's credentials and are never reachable by vendors.
Every call is audited (metadata only; email bodies / questions are never written to the audit log)."""
import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.security import require_permission
from app.services import ai_agents, audit, threat_intel

log = logging.getLogger("freightshield.ai")
router = APIRouter(prefix="/ai", tags=["ai"])
_guard = Depends(require_permission("ai:use"))

_KIND_PREFIX = {
    "chat": "Answer this analyst question",
    "explain_alert": "Explain this Wazuh alert in plain language (what fired, why it matters, what to check next)",
    "incident_summary": "Summarize this incident from the Wazuh evidence",
    "threat_analysis": "Perform a threat analysis (MITRE ATT&CK mapping, severity, confidence)",
    "investigation_guidance": "Give step-by-step investigation guidance",
}


class SocAsk(BaseModel):
    kind: Literal["chat", "explain_alert", "incident_summary", "threat_analysis", "investigation_guidance"] = "chat"
    question: str = Field(min_length=3, max_length=2000)
    alert_id: str | None = Field(None, max_length=128, pattern=r"^[\w.:\-]+$")
    time_range: str = Field("last 24 hours", min_length=2, max_length=100)
    include_threat_intel: bool = True   # Phase 6: append stored IOC reputation/MITRE facts as untrusted reference context


class EmailIn(BaseModel):
    from_address: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=50000)
    to: str | None = Field(None, max_length=500)
    date: str | None = Field(None, max_length=100)
    message_id: str | None = Field(None, max_length=200)
    attachments: list[str] = Field(default_factory=list, max_length=20)


def _ip(r: Request) -> str | None:
    return r.client.host if r.client else None


async def _audited(action: str, request: Request, user: dict, detail: str, call):
    try:
        res = await call
    except ai_agents.AgentUnavailable as e:
        audit.record(user, action, request.url.path, "denied", _ip(request), f"unavailable; {detail}")
        raise HTTPException(503, f"AI agent unavailable: {'; '.join(e.reasons)}") from e
    except Exception as e:
        audit.record(user, action, request.url.path, "denied", _ip(request), f"failed {type(e).__name__}; {detail}")
        raise
    audit.record(user, action, request.url.path, "success", _ip(request), f"{detail}; {res.get('duration_ms')}ms")
    return res


@router.get("/status")
def ai_status(user: dict = _guard):
    """Readiness of both agents. Reports missing prerequisites honestly; does not call the LLM or Wazuh."""
    return ai_agents.status()


@router.post("/soc/ask")
async def soc_ask(body: SocAsk, request: Request, user: dict = _guard):
    req = f"{_KIND_PREFIX[body.kind]}: {body.question}"
    if body.alert_id:
        req += f" (alert id: {body.alert_id})"
    ti_ctx = threat_intel.ai_context(body.question) if body.include_threat_intel else ""
    req += ti_ctx
    res = await _audited("ai_soc_query", request, user, f"kind={body.kind} qlen={len(body.question)} ti_ctx={bool(ti_ctx)}",
                         ai_agents.run_soc(req, body.time_range))
    return {"kind": body.kind, "time_range": body.time_range, **res}


@router.post("/email/analyze")
async def email_analyze(body: EmailIn, request: Request, user: dict = _guard):
    res = await _audited("ai_email_analyze", request, user, f"bodylen={len(body.body)}",
                         ai_agents.run_email(body.model_dump()))
    log.info("email analyzed: department=%s sensitivity=%s escalated=%s", res["department"], res["sensitivity"],
             res["escalate_to_it_security"])
    return res
