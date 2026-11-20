// Admin-only AI agents UI (backend enforces ai:use). Used both as drawers (topbar buttons) and as full pages.
import { api, explain } from "./api.js";
import { h, note, table } from "./dom.js";

const KINDS = { chat: "Ask a question", explain_alert: "Explain an alert", incident_summary: "Incident summary", threat_analysis: "Threat analysis", investigation_guidance: "Investigation guidance" };
const status = async (which, badge) => { try { const s = (await api("/ai/status"))[which]; badge.className = "note " + (s.state === "ready" ? "ok" : "err");
  badge.textContent = `${s.agent}: ${s.state}` + (s.reasons?.length ? ` — ${s.reasons.join("; ")}` : ""); } catch (e) { badge.className = "note err"; badge.textContent = explain(e); } };

export function socPanel() {
  const badge = note("", "Checking agent status…"), log = h("div", { class: "chat" });
  const kind = h("select", { "aria-label": "Request type" }, Object.entries(KINDS).map(([k, v]) => h("option", { value: k }, v)));
  const range = h("input", { value: "last 24 hours", size: "14", "aria-label": "Time range" }), alertId = h("input", { placeholder: "Alert ID (optional)", size: "18" });
  const inp = h("textarea", { rows: "3", maxlength: "2000", placeholder: "Ask about an alert, agent or incident…" }), btn = h("button", {}, "Investigate");
  const add = (who, t, cls = "") => { const m = h("div", { class: "msg " + cls }, h("b", {}, who), h("pre", { class: "pre" }, t)); log.append(m); m.scrollIntoView({ block: "nearest" }); return m; };
  const send = async () => {
    const q = inp.value.trim(); if (q.length < 3) return;
    btn.disabled = true; add("You", q, "me"); const p = add("System", "Investigating with live Wazuh data — this can take a minute", "pending typing");
    try { const r = await api("/ai/soc/ask", { method: "POST", body: { kind: kind.value, question: q, time_range: range.value.trim() || "last 24 hours", ...(alertId.value.trim() ? { alert_id: alertId.value.trim() } : {}) } });
      p.remove(); add("SOC AI", r.report); inp.value = ""; } catch (e) { p.remove(); add("System", explain(e), "err"); }
    btn.disabled = false;
  };
  btn.addEventListener("click", send); inp.addEventListener("keydown", e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send(); });
  status("soc", badge);
  return h("div", {}, h("div", { class: "ai-hero" }, h("span", { class: "ico" }, "✳"), h("div", {}, h("b", {}, "AI SOC Investigator"), h("div", { class: "mu" }, "Read-only Wazuh investigation crew. Answers are text; nothing is changed."))),
    badge, log, h("div", { class: "row wrap" }, kind, range, alertId), inp, h("div", { class: "row", style: "margin-top:8px" }, btn, h("small", {}, "Ctrl/⌘+Enter to send")));
}

export function emailPanel() {
  const badge = note("", "Checking agent status…"), out = h("div", {});
  const f = (ph, size) => h("input", { placeholder: ph, size: String(size || 28), maxlength: "500", "aria-label": ph });
  const from = f("From (sender address)"), subject = f("Subject", 44), to = f("To (optional)");
  const body = h("textarea", { rows: "8", maxlength: "50000", placeholder: "Paste the email body…" }), btn = h("button", {}, "Analyze email");
  btn.addEventListener("click", async () => {
    if (!from.value.trim() || !subject.value.trim() || !body.value.trim()) { out.replaceChildren(note("err", "From, subject and body are required.")); return; }
    btn.disabled = true; out.replaceChildren(note("typing", "Analyzing"));
    try { const r = await api("/ai/email/analyze", { method: "POST", body: { from_address: from.value.trim(), subject: subject.value.trim(), body: body.value, ...(to.value.trim() ? { to: to.value.trim() } : {}) } });
      out.replaceChildren(r.escalate_to_it_security ? note("err", "⚠ Security-related: escalate to IT Security.") : null,
        table(["Department", "Sensitivity", "Department reason", "Sensitivity reason"], [[r.department || "not determined", r.sensitivity || "not determined", r.department_reason || "-", r.sensitivity_reason || "-"]]),
        r.parsed ? table(["Recommended recipient", "Address"], r.recommended_recipients.map(x => [x.role, x.address])) : note("err", "The agent's answer could not be parsed, so no routing is suggested. Raw output below."),
        note("", "Recommendation only — nothing was forwarded or sent."), r.parsed ? null : h("pre", { class: "pre" }, r.raw_output));
    } catch (e) { out.replaceChildren(note("err", explain(e))); }
    btn.disabled = false;
  });
  status("email", badge);
  return h("div", {}, h("div", { class: "ai-hero mail" }, h("span", { class: "ico" }, "✉"), h("div", {}, h("b", {}, "AI Email Router"), h("div", { class: "mu" }, "Classifies an email and recommends recipients. Never sends or forwards."))),
    badge, h("div", { class: "row wrap" }, from, subject, to), body, h("div", { class: "row", style: "margin-top:8px" }, btn), out);
}
