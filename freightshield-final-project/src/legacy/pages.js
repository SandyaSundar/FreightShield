// Page renderers. Each fetches real backend data or shows an honest state (loading / error / empty).
import { api, explain, download } from "./api.js";
import { h, table, note, skeleton, kp, when, toast, drawer, sevBadge, statusBadge, badge, donut, barChart, trendChart, SEV_COLOR, STATUS_COLOR } from "./dom.js";
import { socPanel, emailPanel } from "./ai.js";

async function load(el, fn) {
  el.replaceChildren(skeleton());
  try { el.replaceChildren(await fn()); } catch (e) { el.replaceChildren(note("err", explain(e)), h("button", { class: "sec", onclick: () => load(el, fn) }, "Retry")); }
}
const SEV = ["low", "medium", "high", "critical"];
const opts = (cur, list) => [...new Set([cur, ...list])];
const sel = (cur, list, onchange) => h("select", { onchange: e => onchange(e.target.value) },
  opts(cur, list).map(o => h("option", { value: o, ...(o === cur ? { selected: "" } : {}) }, o)));
const mitre = m => (m || []).map(x => x.id + (x.technique ? ` ${x.technique}` : "")).join(", ") || "-";
const patchAndWarn = async (path, body, after) => { try { await api(path, { method: "PATCH", body }); toast("Updated.", "ok"); if (after) after(); } catch (e) { toast(explain(e), "err"); } };
const agentsOf = d => d?.data?.affected_items || [];
const fmtDur = s => s == null ? "n/a" : s >= 3600 ? `${(s / 3600).toFixed(1)} h` : `${(s / 60).toFixed(1)} min`;
const kv = obj => table(["Field", "Value"], Object.entries(obj).filter(([, v]) => v != null && v !== "").map(([k, v]) => [k, typeof v === "object" ? h("pre", { class: "pre" }, JSON.stringify(v, null, 2)) : String(v)]));
const filterBar = (...c) => h("div", { class: "row wrap" }, ...c);
const fl = (label, ctl) => h("label", { class: "flt" }, label, ctl);

// ---- Agents (shared admin/vendor): live search + status chips + detail drawer
const agentsTable = async path => {
  const all = agentsOf(await api(path));
  if (!all.length) return note("", "No agents reported by Wazuh.");
  let status = "", q = "";
  const body = h("div", {}), chips = h("div", { class: "chips" });
  const draw = () => {
    const rows = all.filter(a => (!status || a.status === status) && (!q || JSON.stringify([a.id, a.name, a.ip, a.os?.name, a.version, a.group]).toLowerCase().includes(q)));
    body.replaceChildren(rows.length ? table(["ID", "Name", "IP", "OS", "Version", "Last keep-alive", "Status"], rows.map(x => [x.id, x.name, x.ip, x.os?.name || "-", x.version || "-", x.lastKeepAlive ? when(x.lastKeepAlive) : "-", statusBadge(x.status)]), { onRow: i => { const a = rows[i];
      drawer(`Agent ${a.id} · ${a.name}`, h("div", {}, h("div", { class: "row" }, statusBadge(a.status)), kv({ id: a.id, name: a.name, ip: a.ip, status: a.status, version: a.version, group: (a.group || []).join?.(", ") || a.group, os: a.os?.name && `${a.os.name} ${a.os.version || ""}`, node: a.node_name, registered: a.dateAdd, last_keep_alive: a.lastKeepAlive, manager: a.manager }))); } }) : note("", "No agents match."));
    chips.replaceChildren(...[["", "All"], ...[...new Set(all.map(a => a.status))].map(s => [s, s.replace("_", " ")])].map(([v, t]) => h("button", { class: "chip" + (status === v ? " on" : ""), type: "button", onclick: () => { status = v; draw(); } }, `${t} (${v ? all.filter(a => a.status === v).length : all.length})`)));
  };
  draw();
  return h("div", {}, filterBar(chips, h("span", { class: "sp" }), h("input", { type: "search", placeholder: "Search agents…", "aria-label": "Search agents", oninput: e => { q = e.target.value.toLowerCase(); draw(); } })), body);
};

// ---- Wazuh alerts (shared): level filter, search, paging, detail drawer
const alertsTable = async path => {
  const [base] = path.split("?"), box = h("div", {}), out = h("div", {});
  const f = { min_level: "", agent_id: "", q: "", page: 1 }; let hits = [];
  const draw = async () => {
    out.replaceChildren(skeleton(3));
    const qs = new URLSearchParams({ limit: 50, page: f.page }); if (f.min_level) qs.set("min_level", f.min_level); if (f.agent_id) qs.set("agent_id", f.agent_id);
    try {
      hits = ((await api(`${base}?${qs}`))?.hits?.hits || []).map(x => x._source).filter(s => !f.q || JSON.stringify(s).toLowerCase().includes(f.q.toLowerCase()));
      out.replaceChildren(hits.length ? table(["Time", "Agent", "Rule", "Level", "Description"], hits.map(s => [when(s.timestamp), s.agent?.name || s.agent?.id, s.rule?.id, h("b", { class: Number(s.rule?.level) >= 12 ? "sev-critical" : Number(s.rule?.level) >= 7 ? "sev-high" : "" }, s.rule?.level ?? "-"), s.rule?.description]),
        { onRow: i => drawer(`Alert · rule ${hits[i].rule?.id}`, h("div", {}, h("p", {}, hits[i].rule?.description), h("h3", {}, "Full event"), h("pre", { class: "pre" }, JSON.stringify(hits[i], null, 2)))) }) : note("", "No alerts returned."),
        h("div", { class: "row" }, h("button", { class: "sec", ...(f.page <= 1 ? { disabled: "" } : {}), onclick: () => { f.page--; draw(); } }, "‹ Prev"), h("span", { class: "mu" }, `Page ${f.page}`), h("button", { class: "sec", ...(hits.length < 1 ? { disabled: "" } : {}), onclick: () => { f.page++; draw(); } }, "Next ›")));
    } catch (e) { out.replaceChildren(note("err", explain(e))); }
  };
  const lvl = h("select", { onchange: e => { f.min_level = e.target.value; f.page = 1; draw(); } }, [["", "Any"], [3, "3+"], [7, "7+ (medium)"], [10, "10+ (high)"], [12, "12+ (critical)"]].map(([v, t]) => h("option", { value: v }, t)));
  const ag = h("input", { placeholder: "e.g. 001", size: "6", maxlength: "10", onchange: e => { f.agent_id = e.target.value.trim(); f.page = 1; draw(); } });
  const q = h("input", { type: "search", placeholder: "Filter this page…", oninput: e => { f.q = e.target.value; clearTimeout(q._t); q._t = setTimeout(draw, 300); } });
  box.append(filterBar(fl("Min level", lvl), fl("Agent ID", ag), fl("Search", q)), out); await draw(); return box;
};

function reportsPage(el, base) {
  const days = h("select", {}, [7, 14, 30, 90, 365].map(d => h("option", { value: d, ...(d === 30 ? { selected: "" } : {}) }, `Last ${d} days`)));
  const msg = h("div", {}), out = h("div", {});
  const dl = (fmt, ds) => h("button", { onclick: async ev => { ev.target.disabled = true;
    try { msg.replaceChildren(note("ok", `Downloaded ${await download(`${base}/export?format=${fmt}&dataset=${ds}&days=${days.value}`)} (export recorded in the audit log).`)); }
    catch (e) { msg.replaceChildren(note("err", explain(e))); } ev.target.disabled = false; } }, `${ds} ${fmt.toUpperCase()}`);
  const render = async () => {
    out.replaceChildren(note("", "Loading…"));
    try {
      const r = await api(`${base}/summary?days=${days.value}`), t = r.totals, m = r.metrics;
            const metric = (l, x) => kp(`${l} (n=${x.count}, median ${fmtDur(x.median_seconds)})`, fmtDur(x.mean_seconds));
      out.replaceChildren(
        note("", `Scope: ${r.scope} · ${r.window.from.slice(0, 10)} to ${r.window.to.slice(0, 10)} UTC · generated ${r.generated_at}`),
        h("div", { class: "kps" }, kp("Alerts", t.alerts), kp("Incidents", t.incidents), kp("Open alerts", t.open_alerts), kp("Open incidents", t.open_incidents),
          kp("Critical/High", t.critical_high_alerts), kp("False positives", t.false_positives), metric("MTTA", m.mtta), metric("MTTR alerts", m.mttr_alerts), metric("MTTR incidents", m.mttr_incidents)),
        r.data_quality.alerts_without_ack_time || r.data_quality.resolved_incidents_without_time
          ? note("", `${r.data_quality.note} Excluded: ${r.data_quality.alerts_without_ack_time} alerts, ${r.data_quality.resolved_incidents_without_time} incidents.`) : null,
        h("div", { class: "grid" }, trendChart("Alert trend (daily)", r.alert_trend), trendChart("Incident trend (daily)", r.incident_trend),
          barChart("Alerts by severity", Object.entries(r.alerts_by_severity), SEV_COLOR), barChart("Incidents by severity", Object.entries(r.incidents_by_severity), SEV_COLOR),
          barChart("Alerts by status", Object.entries(r.alerts_by_status)), barChart("Response actions", Object.entries(r.response_actions)),
          barChart("Top agents", r.top_agents.map(x => [x.agent, x.alerts])), barChart("Top rules", r.top_rules.map(x => [x.rule, x.alerts])),
          barChart(`Threat intel IOCs (${r.threat_intel.iocs})`, Object.entries(r.threat_intel.by_classification))));
    } catch (e) { out.replaceChildren(note("err", explain(e))); }
  };
  days.addEventListener("change", render);
  el.replaceChildren(h("div", { class: "row" }, days, dl("pdf", "summary"), dl("csv", "summary"), dl("csv", "alerts"), dl("csv", "incidents"), dl("pdf", "alerts")), msg, out);
  render();
}

// ---- Phase 8: notifications page (shared by admin and vendor; `base` selects the API, `admin` the extra management panels)
const CAT = { critical_alert: "Critical alert", alert: "Alert", new_incident: "New incident", pending_approval: "Approval needed", threat_intel: "Threat intel", overdue_incident: "Overdue incident" };
const VCAT = ["critical_alert", "alert", "new_incident", "threat_intel"];
const changed = () => window.dispatchEvent(new Event("notif-changed"));
function notificationsPage(el, base, admin) {
  const f = { category: "", severity: "", read: "", page: 1 }, LIMIT = 15;
  const msg = h("div", {}), top = h("div", {}), list = h("div", {}), pager = h("div", { class: "row" }), extra = h("div", {});
  const flash = (cls, t) => msg.replaceChildren(note(cls, t));
  const filt = (key, label, options) => h("label", { class: "flt" }, label, h("select", { onchange: e => { f[key] = e.target.value; f.page = 1; refresh(); } },
    options.map(([v, t]) => h("option", { value: v, ...(f[key] === v ? { selected: "" } : {}) }, t))));
  const act = (label, path, after) => h("button", { class: "sec", onclick: async ev => { ev.target.disabled = true;
    try { await api(path, { method: "POST" }); } catch (e) { flash("err", explain(e)); } ev.target.disabled = false; (after || refresh)(); } }, label);
  const card = n => h("article", { class: `ntf sev-${n.severity}${n.is_read ? "" : " unread"}` },
    h("div", { class: "ntf-head" }, h("span", { class: "badge sev-" + n.severity }, n.severity), h("span", { class: "badge" }, CAT[n.category] || n.category),
      n.escalation_level >= 2 ? h("span", { class: "badge esc" }, "ESCALATED") : null, h("time", {}, when(n.ts)), n.is_read ? null : h("span", { class: "dot", title: "Unread" })),
    h("h4", {}, n.title), n.message ? h("p", {}, n.message) : null,
    h("div", { class: "row" }, n.is_read ? act("Mark unread", `${base}/${n.id}/unread`) : act("Mark read", `${base}/${n.id}/read`),
      admin && n.email_state && n.email_state !== "none" ? h("small", { class: "mu" }, `email: ${n.email_state}`) : null,
      n.alert_id ? h("small", { class: "mu" }, `alert #${n.alert_id}`) : null, n.incident_id ? h("small", { class: "mu" }, `incident #${n.incident_id}`) : null));
  async function refresh() {
    const q = new URLSearchParams({ limit: LIMIT, page: f.page });
    for (const k of ["category", "severity", "read"]) if (f[k]) q.set(k, f[k]);
    list.replaceChildren(note("", "Loading…"));
    try {
      const [s, d] = await Promise.all([api(`${base}/summary`), api(`${base}?${q}`)]);
            top.replaceChildren(h("div", { class: "kps" }, kp("Unread", s.unread), kp("Total", s.total), kp("Unread critical", s.unread_by_severity.critical || 0), kp("Unread high", s.unread_by_severity.high || 0)));
      list.replaceChildren(...(d.items.length ? d.items.map(card) : [note("", "No notifications match these filters.")]));
      const pages = Math.max(1, Math.ceil(d.total / LIMIT));
      pager.replaceChildren(h("button", { class: "sec", ...(f.page <= 1 ? { disabled: "" } : {}), onclick: () => { f.page--; refresh(); } }, "Previous"),
        h("span", { class: "mu" }, `Page ${f.page} of ${pages} · ${d.total} notification(s)`),
        h("button", { class: "sec", ...(f.page >= pages ? { disabled: "" } : {}), onclick: () => { f.page++; refresh(); } }, "Next"));
      changed();
    } catch (e) { list.replaceChildren(note("err", explain(e))); }
  }
  async function prefsPanel() {
    const box = h("div", { class: "card" });
    try {
      const p = await api(`${base}/preferences`);
      const en = h("input", { type: "checkbox", ...(p.email_enabled ? { checked: "" } : {}) });
      const ms = h("select", {}, SEV.map(x => h("option", { value: x, ...(x === p.min_severity ? { selected: "" } : {}) }, x)));
      box.replaceChildren(h("h3", {}, "My email alerts"), h("p", { class: "mu" }, `Sent to ${p.email}${p.saved ? "" : " (default; not saved yet)"}.`),
        h("div", { class: "row" }, h("label", {}, en, " Email me"), h("label", {}, "at or above ", ms),
          h("button", { onclick: async () => { try { await api(`${base}/preferences`, { method: "PUT", body: { email_enabled: en.checked, min_severity: ms.value } }); flash("ok", "Preferences saved."); } catch (e) { flash("err", explain(e)); } } }, "Save")));
    } catch (e) { box.replaceChildren(note("err", explain(e))); }
    return box;
  }
  async function adminPanels() {
    const [st, rules, del] = await Promise.all([api("/notifications/status"), api("/notifications/rules"), api("/notifications/deliveries?limit=10")]);
    const num = (v, min) => h("input", { type: "number", min, value: v, class: "num" });
    const rows = rules.items.map(r => {
      const en = h("input", { type: "checkbox", ...(r.enabled ? { checked: "" } : {}) }), em = h("input", { type: "checkbox", ...(r.email ? { checked: "" } : {}) });
      const sla = num(r.sla_minutes, 5), esc = num(r.escalate_after_minutes, 0);
      return [r.severity, en, em, sla, esc, h("button", { onclick: async () => { try { await api(`/notifications/rules/${r.severity}`, { method: "PUT",
        body: { enabled: en.checked, email: em.checked, sla_minutes: +sla.value, escalate_after_minutes: +esc.value } }); flash("ok", `${r.severity} rule saved.`); } catch (e) { flash("err", explain(e)); } } }, "Save")];
    });
    const run = h("button", { onclick: async ev => { ev.target.disabled = true; flash("", "Running checks…");
      try { const r = await api("/notifications/evaluate", { method: "POST" });
        flash("ok", `${r.overdue} overdue, ${r.pending_approvals} approval, ${r.threat_intel} threat-intel notification(s) created · email sent ${r.email.sent}, failed ${r.email.failed}${r.email.skipped_reason ? ` (email skipped: ${r.email.skipped_reason})` : ""}`); }
      catch (e) { flash("err", explain(e)); } ev.target.disabled = false; refresh(); } }, "Run checks now");
    const test = h("button", { class: "sec", onclick: async ev => { ev.target.disabled = true;
      try { await api("/notifications/test-email", { method: "POST" }); flash("ok", "Test email sent to your own address."); } catch (e) { flash("err", explain(e)); } ev.target.disabled = false; } }, "Send me a test email");
    return h("div", {}, note(st.email_ready ? "ok" : "err", st.email_ready ? `Email delivery ready (TLS: ${st.tls}) · ${st.escalation_contacts} escalation contact(s)` : `Email delivery not active: ${st.email_problem}`),
      h("div", { class: "row" }, run, test), h("h3", {}, "Escalation rules (by severity)"),
      h("p", { class: "mu" }, "SLA: an unresolved incident older than this becomes an overdue notification. Escalate after: extra minutes before it is escalated (0 = never)."),
      table(["Severity", "Notify", "Email", "SLA (min)", "Escalate after (min)", ""], rows),
      h("h3", {}, "Email delivery history"),
      del.items.length ? table(["Time", "To", "Status", "Attempts", "Notification", "Error"], del.items.map(d => [when(d.attempted_at), d.recipient, d.status, d.attempts, d.title, d.error || "-"])) : note("", "No email has been sent yet."));
  }
  el.replaceChildren(msg, top,
    h("div", { class: "row wrap" }, filt("category", "Type", [["", "All"], ...(admin ? Object.keys(CAT) : VCAT).map(k => [k, CAT[k]])]),
      filt("severity", "Severity", [["", "All"], ...[...SEV].reverse().map(x => [x, x])]), filt("read", "Status", [["", "All"], ["false", "Unread"], ["true", "Read"]]),
      h("span", { class: "sp" }), act("Mark all read", `${base}/read-all`)), list, pager, extra);
  refresh();
  prefsPanel().then(p => { extra.append(p); if (admin) adminPanels().then(a => extra.append(a)).catch(e => extra.append(note("err", explain(e)))); });
}

// ---- Phase 9: Threat hunting dashboard. `base` = "/hunting" (admin) or "/vendor/hunting" (own agents only; enforced by the backend).
const TACTIC_LIST = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
  "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
function huntingPage(el, base) {
  const inp = (name, ph, size = 14) => h("input", { name, placeholder: ph, size: String(size), maxlength: "200" });
  const F = {
    hours: h("select", { name: "hours" }, [1, 6, 24, 72, 168, 720].map(v => h("option", { value: v, ...(v === 24 ? { selected: "" } : {}) }, v < 48 ? `Last ${v} h` : `Last ${v / 24} days`))),
    agent_id: inp("agent_id", "001", 6), min_level: h("input", { name: "min_level", type: "number", min: "0", max: "15", class: "num", placeholder: "0" }),
    rule_id: inp("rule_id", "5710", 7), group: inp("group", "sshd", 10), technique: inp("technique", "T1110", 9),
    tactic: h("select", { name: "tactic" }, h("option", { value: "" }, "Any tactic"), TACTIC_LIST.map(t => h("option", { value: t }, t))),
    src_ip: inp("src_ip", "203.0.113.9"), user: inp("user", "root", 10), q: inp("q", "free text in description / log", 24),
  };
  const lbl = { hours: "Time range", agent_id: "Agent ID", min_level: "Min level", rule_id: "Rule ID", group: "Rule group", technique: "MITRE technique",
    tactic: "MITRE tactic", src_ip: "Source IP", user: "User", q: "Search" };
  const qs = () => new URLSearchParams(Object.entries(F).map(([k, e]) => [k, e.value.trim()]).filter(([, v]) => v)).toString();
  const out = h("div", {}), evOut = h("div", {});
  let page = 1;
  const pivot = (k, v) => h("a", { href: "#", title: `Hunt on ${lbl[k]} = ${v}`, onclick: ev => { ev.preventDefault(); F[k].value = v; run(); } }, String(v));

  async function events() {
    evOut.replaceChildren(note("", "Loading events…"));
    try {
      const d = await api(`${base}/events?${qs()}&limit=50&page=${page}`);
      evOut.replaceChildren(h("h3", {}, `Matching Wazuh events (${d.total})`),
        d.items.length ? table(["Time", "Agent", "Rule", "Level", "Description", "Source IP", "User", "MITRE"], d.items.map(e =>
          [e.timestamp, pivot("agent_id", e.agent_id), pivot("rule_id", e.rule_id), e.level, e.description || "-",
           e.src_ip ? pivot("src_ip", e.src_ip) : "-", e.user ? pivot("user", e.user) : "-", mitre(e.mitre)])) : note("", "No Wazuh events match these filters."),
        h("div", { class: "row" }, h("button", { ...(page > 1 ? {} : { disabled: "" }), onclick: () => { page--; events(); } }, "‹ Prev"),
          h("span", { class: "mu" }, `Page ${page}`), h("button", { ...(d.has_more ? {} : { disabled: "" }), onclick: () => { page++; events(); } }, "Next ›")));
    } catch (e) { evOut.replaceChildren(note("err", explain(e))); }
  }

  async function run() {
    page = 1; out.replaceChildren(note("", "Hunting across Wazuh alerts…")); evOut.replaceChildren();
    let d;
    try { d = await api(`${base}/analysis?${qs()}`); } catch (e) { return out.replaceChildren(note("err", explain(e))); }
    const crit = d.behaviours.filter(b => b.severity === "critical").length;
    const kpi = (v, t) => h("div", { class: "kp" }, h("b", {}, v), h("small", {}, t));
    const matrix = d.mitre.length ? h("div", { class: "mitre" }, d.mitre.map(c => h("div", { class: "mcol" },
      h("div", { class: "mhead" }, c.tactic, h("small", {}, ` ${c.count}`)),
      c.techniques.map(t => h("a", { href: "#", class: "mtech" + (t.behaviour_findings ? " beh" : ""), title: `${t.wazuh_alerts} Wazuh alert(s), ${t.behaviour_findings} behaviour finding(s)`,
        onclick: ev => { ev.preventDefault(); F.technique.value = t.id.split(".")[0]; run(); } }, h("b", {}, t.id), " ", t.name || ""))))) : note("", "No MITRE ATT&CK techniques in this range.");
    out.replaceChildren(
      h("div", { class: "kps" }, kpi(d.total_events, "Wazuh events matched"), kpi(d.behaviours.length, "Suspicious behaviours"), kpi(crit, "Critical behaviours"),
        kpi(d.correlations.length, "Correlated chains"), kpi(d.mitre.reduce((n, c) => n + c.techniques.length, 0), "ATT&CK techniques")),
      d.truncated ? note("", `Behaviour analysis covered the newest ${d.analyzed_events} of ${d.total_events} events; counts and the matrix cover all. Narrow the filters for full coverage.`) : "",
      h("div", { class: "grid" },
        h("div", { class: "card wide" }, h("h3", {}, "MITRE ATT&CK coverage"), matrix, h("small", { class: "mu" }, "Outlined = also inferred by behaviour analysis. Click a technique to hunt on it.")),
        h("div", { class: "card wide" }, h("h3", {}, "Suspicious behaviour"), d.behaviours.length ? table(["Severity", "Behaviour", "Where", "Agents", "Events", "MITRE", "Last seen"],
          d.behaviours.map(b => [sevBadge(b.severity), h("span", { title: b.description }, b.name), b.src_ip ? pivot("src_ip", b.src_ip) : (b.account || (b.paths || []).join(", ") || (b.tactics || []).join(" → ") || b.group),
            b.agents.join(", "), b.event_count, mitre(b.mitre), b.last_seen])) : note("", "No suspicious behaviour detected in this range.")),
        h("div", { class: "card wide" }, h("h3", {}, "Alert correlation (per-agent activity chains)"), d.correlations.length ? table(["Risk", "Score", "Agent", "Window", "Events", "Tactics", "Sources", "Behaviours", "Detections"],
          d.correlations.map(c => [sevBadge(c.risk), c.score, pivot("agent_id", c.agent_id), `${c.first_seen} → ${c.last_seen}`, c.event_count, c.tactics.join(" → ") || "-",
            c.src_ips.join(", ") || "-", c.behaviours.join(", ") || "-", c.detection_alert_ids.join(", ") || "-"])) : note("", "No correlated activity chains.")),
        barChart("Top agents", d.stats.top_agents.map(a => [a.agent_name || a.agent_id, a.count])),
        barChart("Top rules", d.stats.top_rules.map(r => [`${r.rule_id} ${r.description || ""}`, r.count])),
        barChart("Top source IPs", d.stats.top_src_ips.map(x => [x.value, x.count])),
        barChart("Alert levels", d.stats.levels.map(([l, n]) => [`level ${l}`, n]))),
    );
    events();
  }
  el.replaceChildren(h("div", { class: "row wrap" }, Object.entries(F).map(([k, e]) => h("label", { class: "flt" }, lbl[k], e)),
    h("button", { onclick: run }, "Hunt"), h("button", { onclick: () => { Object.values(F).forEach(e => { e.value = ""; }); F.hours.value = "24"; run(); } }, "Reset")), out, evOut);
  Object.values(F).forEach(e => e.addEventListener("keydown", ev => ev.key === "Enter" && run()));
  run();
}

export const pages = {
  dashboard: (el, user) => load(el, async () => {
    const [health, manager, indexer, agents, d, alerts] = await Promise.all([
      api("/health"),
      api("/wazuh/manager/info"),
      api("/wazuh/indexer/health"),
      api("/wazuh/manager/agents"),
      api("/detections/summary"),
      api("/wazuh/indexer/alerts?limit=12&page=1"),
    ]);
    const a = agentsOf(agents);
    const n = s => a.filter(x => x.status === s).length;
    const open = Object.values(d.open_alerts_by_severity).reduce((x, y) => x + y, 0);
        const hits = alerts?.hits?.hits || [];
    const latest = hits.length ? table(["Observed at", "Agent", "Rule", "Level", "Wazuh description"], hits.map(({ _source: s }) => [when(s.timestamp) || "-", s.agent?.name || s.agent?.id || "-", s.rule?.id || "-", s.rule?.level ?? "-", s.rule?.description || "-"])) : note("", "No alerts returned for the current period.");
    return h("div", {},
      h("div", { class: "ops-intro" }, h("div", {}, h("div", { class: "ops-overline" }, "SECURITY OPERATIONS · LIVE DATA"), h("p", {}, "Wazuh manager inventory, detections, and alert activity.")),
        h("span", { class: "source-label" }, "SOURCE · FREIGHTSHIELD API")),
      h("div", { class: "kps" }, kp("Managed agents", a.length), kp("Active", n("active")),
        kp("Disconnected", n("disconnected")), kp("Never connected", n("never_connected")),
        kp("Open alerts", open), kp("Critical / high", (d.open_alerts_by_severity.critical || 0) + (d.open_alerts_by_severity.high || 0)),
        kp("Open incidents", d.open_incidents), kp("Unread notifications", d.unread_notifications)),
      h("div", { class: "integration-strip" },
        h("div", {}, h("span", {}, "FREIGHTSHIELD API"), h("strong", {}, health.status || "—"), h("small", {}, health.environment || "Environment unavailable")),
        h("div", {}, h("span", {}, "WAZUH MANAGER"), h("strong", {}, manager.data?.title || manager.data?.name || manager.data?.version || "Connected"), h("small", {}, health.integrations?.wazuh_manager_configured ? "Configured on backend" : "Not configured")),
        h("div", {}, h("span", {}, "INDEXER CLUSTER"), h("strong", {}, indexer.status || indexer.cluster_name || "Connected"), h("small", {}, health.integrations?.wazuh_indexer_configured ? "Configured on backend" : "Not configured"))),
      h("div", { class: "grid" },
        donut("Agents by status", ["active", "disconnected", "never_connected", "pending"].map(k => [k, n(k)]).filter(([, v]) => v), STATUS_COLOR),
        donut("Open detection alerts by severity", SEV.slice().reverse().map(k => [k, d.open_alerts_by_severity[k] || 0]).filter(([, v]) => v), SEV_COLOR),
        barChart("Latest alerts by Wazuh level", Object.entries(hits.reduce((m, { _source: s }) => { const k = `level ${s.rule?.level ?? "?"}`; m[k] = (m[k] || 0) + 1; return m; }, {})))),
      h("section", { class: "panel-section" }, h("div", { class: "section-heading" }, h("h3", {}, "Latest Wazuh activity"), h("span", {}, "12 newest indexed alerts")), latest));
  }),

  detections(el) {
    const msg = h("span", { class: "mu" }), body = h("div", {}), f = { status: "", severity: "" };
    const run = h("button", { onclick: async ev => { ev.target.disabled = true; msg.textContent = "Scanning Wazuh…";
      try { const r = await api("/detections/run", { method: "POST" });
        msg.textContent = `Read ${r.events} real events · ${r.created.length} new, ${r.updated.length} updated alerts${r.truncated ? " (truncated)" : ""}`; toast("Detection run complete.", "ok"); load(body, listAlerts); }
      catch (e) { msg.textContent = explain(e); toast(explain(e), "err"); } ev.target.disabled = false; } }, "Run detection now");
    const listAlerts = async () => {
      const q = new URLSearchParams({ limit: 50 }); for (const k of ["status", "severity"]) if (f[k]) q.set(k, f[k]);
      const d = await api(`/detections/alerts?${q}`);
      if (!d.items.length) return note("", "No alerts match.");
      return table(["Last seen", "Severity", "Alert", "Agent", "MITRE ATT&CK", "Events", "Status"], d.items.map(a =>
        [when(a.last_seen), sevBadge(a.severity), a.title, a.agent_name || a.agent_id, mitre(a.mitre), a.event_count,
         sel(a.status, ["acknowledged", "investigating", "resolved", "false_positive"], v => patchAndWarn(`/detections/alerts/${a.id}`, { status: v }, () => load(body, listAlerts)))]),
        { onRow: async i => { const a = d.items[i]; const box = h("div", {}, skeleton(3)); drawer(`Alert #${a.id} · ${a.title}`, box);
          try { const full = await api(`/detections/alerts/${a.id}`); box.replaceChildren(h("div", { class: "row" }, sevBadge(full.severity), statusBadge(full.status)), kv(full)); } catch (e) { box.replaceChildren(note("err", explain(e))); } } });
    };
    const flt = (key, label, list) => fl(label, h("select", { onchange: e => { f[key] = e.target.value; load(body, listAlerts); } }, [["", "All"], ...list.map(x => [x, x])].map(([v, t]) => h("option", { value: v }, t))));
    el.replaceChildren(filterBar(run, flt("severity", "Severity", SEV.slice().reverse()), flt("status", "Status", ["open", "acknowledged", "investigating", "resolved", "false_positive"]), msg), body); load(body, listAlerts);
  },

  incidents(el) {
    const body = h("div", {}), f = { status: "" };
    const list = async () => {
      const q = new URLSearchParams({ limit: 50 }); if (f.status) q.set("status", f.status);
      const d = await api(`/detections/incidents?${q}`);
      if (!d.items.length) return note("", "No incidents.");
      return table(["ID", "Title", "Severity", "Agent", "Alerts", "MITRE ATT&CK", "Last activity", "Status"], d.items.map(i =>
        [i.id, i.title, sevBadge(i.severity), i.agent_id, i.alert_count, mitre(i.mitre), when(i.last_activity),
         sel(i.status, ["open", "investigating", "resolved"], v => patchAndWarn(`/detections/incidents/${i.id}`, { status: v }, () => load(body, list)))]),
        { onRow: async idx => { const i = d.items[idx]; const box = h("div", {}, skeleton(3)); drawer(`Incident #${i.id} · ${i.title}`, box);
          try { const full = await api(`/detections/incidents/${i.id}`); const { alerts, ...rest } = full;
            box.replaceChildren(h("div", { class: "row" }, sevBadge(full.severity), statusBadge(full.status)), kv(rest),
              Array.isArray(alerts) && alerts.length ? h("div", {}, h("h3", {}, "Linked alerts"), table(["ID", "Severity", "Title", "Status"], alerts.map(a => [a.id, sevBadge(a.severity), a.title, a.status]))) : null); }
          catch (e) { box.replaceChildren(note("err", explain(e))); } } });
    };
    el.replaceChildren(filterBar(fl("Status", h("select", { onchange: e => { f.status = e.target.value; load(body, list); } }, [["", "All"], ["open", "open"], ["investigating", "investigating"], ["resolved", "resolved"]].map(([v, t]) => h("option", { value: v }, t))))), body);
    load(body, list);
  },

  rules: el => load(el, async () => {
    const { items } = await api("/detections/rules");
    return table(["Rule", "Enabled", "Count threshold", "Window (s)", "Min Wazuh level", "Severity", ""], items.map(r => {
      const en = h("input", { type: "checkbox", ...(r.enabled ? { checked: "" } : {}) });
      const th = h("input", { type: "number", min: 1, value: r.threshold }), w = h("input", { type: "number", min: 30, value: r.window_seconds });
      const lv = h("input", { type: "number", min: 0, max: 15, value: r.min_level });
      let sev = r.severity;
      return [r.name, en, th, w, lv, sel(r.severity, SEV, v => { sev = v; }),
        h("button", { onclick: async () => { try { await api(`/detections/rules/${r.rule_key}`, { method: "PUT",
          body: { enabled: en.checked, threshold: +th.value, window_seconds: +w.value, min_level: +lv.value, severity: sev } });
          toast("Rule saved.", "ok"); } catch (e) { toast(explain(e), "err"); } } }, "Save")];
    }));
  }),

  // ---- Phase 8: Notifications & Escalation. Admin sees everything; vendors only their own agents (enforced by the backend).
  notifications: el => notificationsPage(el, "/notifications", true),
  "vendor-notifications": el => notificationsPage(el, "/vendor/notifications", false),

  "vendor-detections": el => load(el, async () => {
    const [a, i] = await Promise.all([api("/vendor/detections/alerts?limit=50"), api("/vendor/detections/incidents?limit=50")]);
    return h("div", {}, h("h3", {}, "Alerts on your agents"),
      a.items.length ? table(["Last seen", "Severity", "Alert", "Agent", "MITRE ATT&CK", "Status"], a.items.map(x => [x.last_seen, x.severity, x.title, x.agent_name || x.agent_id, mitre(x.mitre), x.status])) : note("", "No alerts on your agents."),
      h("h3", {}, "Incidents"),
      i.items.length ? table(["ID", "Title", "Severity", "Alerts", "Status"], i.items.map(x => [x.id, x.title, x.severity, x.alert_count, x.status])) : note("", "No incidents."));
  }),

  agents: el => load(el, () => agentsTable("/wazuh/manager/agents")),
  alerts: el => load(el, () => alertsTable("/wazuh/indexer/alerts?limit=50")),
  "vendor-agents": el => load(el, () => agentsTable("/vendor/agents")),   // only agents assigned to this vendor
  "vendor-alerts": el => load(el, () => alertsTable("/vendor/alerts?limit=50")),

  // ---- Phase 4: AI agents (Admin only; backend enforces ai:use). Shared UI lives in ai.js.
  ai: el => el.replaceChildren(socPanel()),
  email: el => el.replaceChildren(emailPanel()),

  // ---- Phase 5: Incident Response. All state changes go through the backend (admin + approval); the UI only displays.
  response(el) {
    const root = h("div", {}), msg = h("div", {});
    const flash = (cls, t) => msg.replaceChildren(note(cls, t));
    const act = (label, path, body, confirmText, method = "POST") => h("button", { onclick: async ev => {
      if (confirmText && !window.confirm(confirmText)) return;
      const b = typeof body === "function" ? body() : body;
      if (b === null) return;  // user cancelled a prompt
      ev.target.disabled = true;
      try { await api(path, { method, body: b }); flash("ok", label + " submitted."); } catch (e) { flash("err", explain(e)); }
      render();
    } }, label);
    const what = a => `${a.action} ${a.target || ""} on agent ${a.agent_id}`.trim();
    async function render() {
      root.replaceChildren(note("", "Loading…"));
      try {
        const [sm, pend, hist, aud] = await Promise.all([api("/ir/summary"), api("/ir/actions?status=pending&limit=50"),
          api("/ir/actions?limit=50"), api("/ir/audit?limit=15")]);
        const cap = sm.capabilities, c = sm.audit_chain;
                const history = hist.items.filter(a => a.status !== "pending");
        root.replaceChildren(
          h("div", { class: "kps" }, kp("Pending approvals", sm.pending_approvals), kp("Executed", sm.actions_by_status.executed || 0),
            kp("Failed", (sm.actions_by_status.failed || 0) + (sm.actions_by_status.rollback_failed || 0)), kp("Rolled back", sm.actions_by_status.rolled_back || 0)),
          note(cap.execution_enabled ? "ok" : "err", cap.execution_enabled ? "Execution enabled — every action still needs administrator approval."
            : "Execution is DISABLED on the server (IR_EXECUTION_ENABLED=false): approvals will be refused and nothing runs."),
          note("", `Wazuh Manager: ${cap.wazuh_manager_configured ? "configured" : "not configured"} · Block IP: ${cap.block_ip.supported ? "supported" : "not configured"}`
            + ` (rollback ${cap.block_ip.rollback ? "yes" : "manual"}) · Isolate agent: ${cap.isolate_agent.supported ? "supported" : "not configured"}`
            + ` (rollback ${cap.isolate_agent.rollback ? "yes" : "manual"}) · Audit chain: ${c.valid ? "valid" : "BROKEN at #" + c.first_bad_id} (${c.entries} entries)`),
          h("h3", {}, "Playbooks"),
          table(["Playbook", "Trigger", "Min severity", "Steps", "Status", ""], sm.playbooks.map(p => [p.name, p.trigger_rule, p.min_severity,
            p.steps.map(x => x.type).join(", "), p.enabled ? "enabled" : "disabled",
            act(p.enabled ? "Disable" : "Enable", `/ir/playbooks/${p.key}`, { enabled: !p.enabled }, undefined, "PUT")])),
          h("h3", {}, "Pending approvals"),
          pend.items.length ? table(["ID", "Severity", "Action", "Alert", "Created", ""], pend.items.map(a => [a.id, a.severity, what(a), a.alert_id, a.created_at,
            h("span", {}, act("Approve & execute", `/ir/actions/${a.id}/approve`, undefined, `Execute: ${what(a)}?\nThis changes a live system.`),
              act("Reject", `/ir/actions/${a.id}/reject`, () => { const r = (window.prompt("Reason for rejecting (min 3 characters):") || "").trim(); return r.length >= 3 ? { reason: r } : null; }))]))
            : note("", "No actions awaiting approval."),
          h("h3", {}, "Execution history"),
          history.length ? table(["ID", "Status", "Action", "Approved by", "Executed", "Error", ""], history.map(a => [a.id, a.status, what(a), a.approved_by || "-", a.executed_at || "-", a.error || a.detail || "-",
            a.status === "failed" ? act("Retry", `/ir/actions/${a.id}/retry`, undefined, `Retry: ${what(a)}?`)
              : ["executed", "rollback_failed"].includes(a.status) ? act("Roll back", `/ir/actions/${a.id}/rollback`, undefined, `Roll back: ${what(a)}?`) : ""]))
            : note("", "No executions yet."),
          h("h3", {}, "Recent audit trail (append-only, hash-chained)"),
          table(["#", "Time", "Actor", "Action", "Event", "Detail"], aud.items.map(x => [x.id, x.ts, x.actor, x.action_id ?? "-", x.event, x.detail || "-"])));
      } catch (e) { root.replaceChildren(note("err", explain(e))); }
    }
    const aid = h("input", { placeholder: "Alert ID", size: "8" });
    const rec = h("button", { onclick: async () => {
      try { const r = await api(`/ir/recommend/${encodeURIComponent(aid.value.trim())}`, { method: "POST" });
        flash("ok", `${r.actions.length} action(s) recommended (pending approval); ${r.skipped.length} skipped.`); } catch (e) { flash("err", explain(e)); }
      render();
    } }, "Recommend response");
    el.replaceChildren(h("h2", {}, "Incident Response"), msg, h("div", { class: "row" }, aid, rec), root);
    render();
  },
  "vendor-response": el => load(el, async () => {
    const r = await api("/vendor/ir/actions?limit=50");
    return r.items.length ? table(["ID", "Agent", "Action", "Severity", "Status", "Executed"], r.items.map(a => [a.id, a.agent_id, a.action, a.severity, a.status, a.executed_at || "-"]))
      : note("", "No response actions on your agents.");
  }),

  // ---- Phase 6: Threat Intelligence. Scores come from the backend's feed enrichment; a missing score means no feed answered.
  threatintel(el) {
    const msg = h("div", {}), root = h("div", {}), detail = h("div", {});
    const flash = (cls, t) => msg.replaceChildren(note(cls, t));
    const score = i => i.score == null ? "n/a" : `${i.score} (${i.risk})`;
    const feeds = f => Object.entries(f || {}).map(([k, v]) => `${k}: ${v.configured ? "configured" : "no key"}`).join(" · ");
    async function show(id) {
      detail.replaceChildren(note("", "Loading…"));
      try {
        const d = await api(`/ti/iocs/${id}`);
        detail.replaceChildren(h("h3", {}, `${d.type.toUpperCase()} ${d.value}`),
          note(d.classification === "malicious" ? "err" : "", `Score ${score(d)} · ${d.classification} · ${d.sighting_count} sighting(s) on agents ${d.agents.join(", ") || "-"}`),
          h("h3", {}, "Feed verdicts"),
          table(["Feed", "Status", "Score", "Detail", "Fetched"], d.enrichments.map(e => [e.provider, e.status, e.score ?? "-", JSON.stringify(e.summary), e.fetched_at])),
          h("h3", {}, "MITRE ATT&CK (evidence-based)"),
          d.mitre.length ? table(["ID", "Tactic", "Technique", "Source", "Evidence"], d.mitre.map(m => [m.id, m.tactic || "-", m.technique || "-", m.source, m.evidence])) : note("", "No technique is supported by the evidence."),
          h("h3", {}, "Wazuh sightings"),
          table(["Time", "Agent", "Rule", "Level", "Alert"], d.sightings.map(s => [s.ts, s.agent_id, s.rule_id, s.level, s.wazuh_alert_id])),
          h("button", { onclick: async () => { try { await api(`/ti/iocs/${id}/refresh`, { method: "POST" }); show(id); render(); } catch (e) { flash("err", explain(e)); } } }, "Re-check feeds"));
      } catch (e) { detail.replaceChildren(note("err", explain(e))); }
    }
    async function render() {
      root.replaceChildren(note("", "Loading…"));
      try {
        const [sm, st, list, cor] = await Promise.all([api("/ti/summary"), api("/ti/status"), api("/ti/iocs?limit=50"), api("/ti/correlations")]);
                root.replaceChildren(
          h("div", { class: "kps" }, kp("IOCs", sm.total_iocs), kp("Malicious", sm.by_classification.malicious || 0), kp("Suspicious", sm.by_classification.suspicious || 0), kp("Unscored", sm.by_classification.unknown || 0)),
          note(Object.values(st.feeds).some(f => f.configured) ? "" : "err", "Feeds — " + feeds(st.feeds)),
          h("h3", {}, "Indicators"),
          list.items.length ? table(["Type", "Indicator", "Score", "Class", "Sightings", "MITRE", "Last seen", ""], list.items.map(i =>
            [i.type, i.value, score(i), i.classification, i.sighting_count, mitre(i.mitre), i.last_seen, h("button", { onclick: () => show(i.id) }, "Details")]))
            : note("", "No IOCs yet. Run a scan to extract indicators from Wazuh alerts."),
          h("h3", {}, "Correlated attack patterns"),
          cor.items.length ? table(["Pattern", "Risk", "Summary", "Agents", "Alerts", "Detections", "Last seen"], cor.items.map(p =>
            [p.pattern, p.risk, p.summary, p.agents.join(", "), p.alerts, (p.detection_alert_ids || []).join(", ") || "-", p.last_seen])) : note("", "No correlated patterns."),
          detail);
      } catch (e) { root.replaceChildren(note("err", explain(e))); }
    }
    const scan = h("button", { onclick: async ev => { ev.target.disabled = true; flash("", "Scanning Wazuh and querying feeds…");
      try { const r = await api("/ti/scan", { method: "POST" }); const p = Object.entries(r.feed_problems).map(([k, v]) => `${k}: ${Object.entries(v).map(([a, b]) => `${a}×${b}`).join(",")}`).join("; ");
        flash(p ? "err" : "ok", `${r.alerts_read} alerts read · ${r.new_iocs} new IOCs · ${r.enriched} enriched · ${r.deferred} deferred${p ? " · feed problems — " + p : ""}`); } catch (e) { flash("err", explain(e)); }
      ev.target.disabled = false; render(); } }, "Scan alerts for IOCs");
    const val = h("input", { placeholder: "IP, domain, URL or file hash", size: "46", maxlength: "2048" });
    const look = h("button", { onclick: async () => { if (!val.value.trim()) return; try { const d = await api("/ti/lookup", { method: "POST", body: { value: val.value.trim() } }); render(); show(d.id); } catch (e) { flash("err", explain(e)); } } }, "Look up");
    el.replaceChildren(msg, h("div", { class: "row" }, scan, val, look), root);
    render();
  },
  "vendor-threatintel": el => load(el, async () => {
    const [l, c] = await Promise.all([api("/vendor/ti/iocs?limit=50"), api("/vendor/ti/correlations")]);
    return h("div", {}, h("h3", {}, "Indicators seen on your agents"),
      l.items.length ? table(["Type", "Indicator", "Score", "Class", "Sightings", "Last seen"], l.items.map(i => [i.type, i.value, i.score ?? "n/a", i.classification, i.sighting_count, i.last_seen])) : note("", "No indicators on your agents."),
      h("h3", {}, "Patterns"), c.items.length ? table(["Pattern", "Risk", "Summary", "Alerts"], c.items.map(p => [p.pattern, p.risk, p.summary, p.alerts])) : note("", "No correlated patterns."));
  }),

  // ---- Phase 7: Reports & Analytics. Real data only; `base` selects the admin or the vendor-scoped (own agents) API.
  reports: el => reportsPage(el, "/reports"),
  "vendor-reports": el => reportsPage(el, "/vendor/reports"),

  hunting: el => huntingPage(el, "/hunting"),
  "vendor-hunting": el => huntingPage(el, "/vendor/hunting"),

  profile: el => load(el, async () => {
    const account = await api("/rbac/me");
    return h("section", { class: "panel-section profile-panel" },
      h("div", { class: "profile-avatar" }, (account.email || "F").slice(0, 1).toUpperCase()),
      h("div", { class: "profile-details" },
        h("div", {}, h("span", {}, "SIGNED-IN ACCOUNT"), h("strong", {}, account.email)),
        h("div", {}, h("span", {}, "ROLE"), h("strong", {}, account.role_label)),
        h("div", {}, h("span", {}, "ACCESS PROVIDED BY API"), h("strong", {}, (account.permissions || []).length ? account.permissions.join(" · ") : "No security-data access"))));
  }),

  users: el => load(el, async () => {
    const [listResult, rolesResult, agentsResult] = await Promise.allSettled([api("/users?limit=100"), api("/rbac/roles"), api("/wazuh/manager/agents?limit=500")]);
    if (listResult.status === "rejected") throw listResult.reason;
    if (rolesResult.status === "rejected") throw rolesResult.reason;
    const list = listResult.value, roles = rolesResult.value;
    const agents = agentsResult.status === "fulfilled" ? agentsResult.value : { data: { affected_items: [] } };
    const usersBody = h("div", {});
    const msg = h("div", {});
    const flash = (kind, text) => msg.replaceChildren(note(kind, text));
    const email = h("input", { type: "email", required: "", maxlength: "254", placeholder: "person@company.com", "aria-label": "New user's email" });
    const role = h("select", { "aria-label": "New user's role" }, ["user", "vendor", "admin"].map(value => h("option", { value }, roles.labels?.[value] || value)));
    const add = h("button", { type: "button", onclick: async () => {
      if (!email.value.trim()) return flash("err", "Enter a valid email address.");
      add.disabled = true;
      try { await api("/users", { method: "POST", body: { email: email.value.trim(), role: role.value } }); flash("ok", "User added. They can sign in after their account is registered."); load(usersBody, renderUsers); }
      catch (e) { flash("err", explain(e)); }
      add.disabled = false;
    } }, "Add user");

    const renderUsers = async () => {
      const refresh = await api("/users?limit=100");
      const roleOptions = ["admin", "user", "vendor"];
      usersBody.replaceChildren(table(["Email", "Role", "Account", "Role change", "Vendor agents", ""], refresh.items.map(u => {
        const roleSelect = sel(u.role, roleOptions, async value => {
          try { await api(`/users/${u.id}`, { method: "PATCH", body: { role: value } }); flash("ok", `Updated role for ${u.email}.`); load(usersBody, renderUsers); }
          catch (e) { flash("err", explain(e)); load(usersBody, renderUsers); }
        });
        const statusButton = h("button", { class: "sec", onclick: async () => {
          try { await api(`/users/${u.id}`, { method: "PATCH", body: { active: !u.active } }); flash("ok", `Account ${u.active ? "disabled" : "enabled"}.`); load(usersBody, renderUsers); }
          catch (e) { flash("err", explain(e)); }
        } }, u.active ? "Disable" : "Enable");
        let vendorTools = "—";
        if (u.role === "vendor") {
          const agentOptions = agentsOf(agents).map(a => h("option", { value: a.id }, `${a.id} · ${a.name || a.ip || "Wazuh agent"}`));
          const agentSelect = h("select", { "aria-label": `Wazuh agent for ${u.email}` }, [h("option", { value: "" }, "Choose agent"), ...agentOptions]);
          const assign = h("button", { class: "sec", onclick: async () => {
            if (!agentSelect.value) return flash("err", "Select a Wazuh agent first.");
            assign.disabled = true;
            try { await api(`/vendors/${u.id}/agents/${encodeURIComponent(agentSelect.value)}`, { method: "PUT" }); flash("ok", `Assigned agent ${agentSelect.value} to ${u.email}.`); }
            catch (e) { flash("err", explain(e)); }
            assign.disabled = false;
          } }, "Assign");
          const listAgents = h("button", { class: "sec", onclick: async () => {
            try {
              const data = await api(`/vendors/${u.id}/agents`);
              const assigned = data.agent_ids || [];
              if (!assigned.length) vendorTools.replaceChildren(agentSelect, assign, listAgents, note("", `No Wazuh agents are assigned to ${u.email}.`));
              else vendorTools.replaceChildren(agentSelect, assign, listAgents, ...assigned.map(agentId => h("button", { class: "sec", onclick: async ev => {
                ev.target.disabled = true;
                try { await api(`/vendors/${u.id}/agents/${encodeURIComponent(agentId)}`, { method: "DELETE" }); flash("ok", `Removed agent ${agentId} from ${u.email}.`); listAgents.click(); }
                catch (e) { flash("err", explain(e)); ev.target.disabled = false; }
              } }, `Unassign ${agentId}`)));
              flash("", assigned.length ? `${assigned.length} assigned agent(s) shown below ${u.email}.` : `No Wazuh agents are assigned to ${u.email}.`);
            } catch (e) { flash("err", explain(e)); }
          } }, "View scope");
          vendorTools = h("div", { class: "row wrap" }, agentSelect, assign, listAgents);
        }
        const remove = h("button", { class: "sec", onclick: async () => {
          if (!window.confirm(`Delete ${u.email}? This removes their FreightShield account and assigned vendor agents.`)) return;
          try { await api(`/users/${u.id}`, { method: "DELETE" }); flash("ok", "User deleted."); load(usersBody, renderUsers); }
          catch (e) { flash("err", explain(e)); }
        } }, "Delete");
        return [u.email, roles.labels?.[u.role] || u.role, u.active ? "Active" : "Disabled", roleSelect, vendorTools, h("div", { class: "row" }, statusButton, remove)];
      })));
    };
    await renderUsers();
    return h("div", {}, h("div", { class: "panel-section" }, h("h3", {}, "Register a user"), h("p", { class: "mu" }, "Google sign-in is limited to registered active accounts. The backend enforces all role permissions."), h("div", { class: "row wrap" }, email, role, add)), msg,
      agentsResult.status === "rejected" ? note("err", `Wazuh agent inventory is unavailable; vendor assignments cannot be selected right now. ${explain(agentsResult.reason)}`) : null,
      h("div", { class: "section-heading" }, h("h3", {}, "Accounts & vendor assignments"), h("span", {}, `${Number.isFinite(list.total) ? list.total : list.items.length} registered`)), usersBody);
  }),

  audit: el => load(el, async () => {
    const filter = h("select", {}, [["", "All outcomes"], ["success", "Success"], ["denied", "Denied"], ["failure", "Failure"]].map(([v, label]) => h("option", { value: v }, label)));
    const out = h("div", {}), message = h("div", {});
    const render = async () => {
      out.replaceChildren(note("", "Loading audit entries…"));
      try {
        const q = new URLSearchParams({ limit: "50", page: "1" });
        if (filter.value) q.set("outcome", filter.value);
        const [data, chain] = await Promise.all([api(`/audit/logs?${q}`), api("/ir/audit/verify")]);
        const verify = h("div", { class: `note ${chain.valid ? "ok" : "err"}` }, chain.valid ? `Incident-response audit chain is valid · ${chain.entries} entries.` : `Incident-response audit chain is invalid at entry ${chain.first_bad_id}.`);
        out.replaceChildren(verify, data.items.length ? table(["Time", "Actor", "Action", "Target", "Outcome", "Detail"], data.items.map(x => [x.ts, x.actor_email || "System", x.action, x.target || "—", x.outcome, x.detail || "—"])) : note("", "No audit entries match this filter."));
      } catch (e) { out.replaceChildren(note("err", explain(e))); }
    };
    filter.addEventListener("change", render);
    const controls = h("div", { class: "row wrap" }, h("label", { class: "flt" }, "Outcome", filter), h("button", { class: "sec", onclick: render }, "Refresh audit"));
    const panel = h("div", {}, h("div", { class: "panel-section" }, h("h3", {}, "Security event audit"), h("p", { class: "mu" }, "Read-only audit records from the source API. Incident-response chain verification is checked alongside the event list.")), controls, message, out);
    render();
    return panel;
  }),
};
