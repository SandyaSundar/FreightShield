// Page renderers. Each fetches real backend data or shows an honest state (loading / error / empty).
import { api, explain } from "./api.js";
import { h, table } from "./dom.js";

const note = (cls, msg) => h("div", { class: "note " + cls }, msg);
async function load(el, fn) {
  el.replaceChildren(note("", "Loading…"));
  try { el.replaceChildren(await fn()); } catch (e) { el.replaceChildren(note("err", explain(e))); }
}
const agentsOf = d => d?.data?.affected_items || [];

export const pages = {
  dashboard: el => load(el, async () => {
    const a = agentsOf(await api("/wazuh/manager/agents"));
    const n = s => a.filter(x => x.status === s).length;
    const kp = (l, v) => h("div", { class: "kp" }, h("b", {}, v), h("small", {}, l));
    return h("div", { class: "kps" }, kp("Agents", a.length), kp("Active", n("active")),
      kp("Disconnected", n("disconnected")), kp("Never connected", n("never_connected")));
  }),

  agents: el => load(el, async () => {
    const a = agentsOf(await api("/wazuh/manager/agents"));
    if (!a.length) return note("", "No agents reported by Wazuh.");
    return table(["ID", "Name", "IP", "OS", "Status"], a.map(x => [x.id, x.name, x.ip, x.os?.name || "-", x.status]));
  }),

  alerts: el => load(el, async () => {
    // Expected backend route (not built yet): GET /api/wazuh/indexer/alerts?limit=50 -> { hits: { hits: [{_source}] } }
    const hits = (await api("/wazuh/indexer/alerts?limit=50"))?.hits?.hits || [];
    if (!hits.length) return note("", "No alerts returned.");
    return table(["Time", "Agent", "Rule", "Level", "Description"], hits.map(({ _source: s }) =>
      [s.timestamp, s.agent?.name, s.rule?.id, s.rule?.level, s.rule?.description]));
  }),

  incidents: el => load(el, async () => {
    // Expected backend route (not built yet): GET /api/incidents -> { items: [...] }
    const items = (await api("/incidents"))?.items || [];
    if (!items.length) return note("", "No incidents.");
    return table(["ID", "Title", "Severity", "Status", "Assignee"], items.map(i => [i.id, i.title, i.severity, i.status, i.assignee]));
  }),

  ai(el) {
    const log = h("div", { class: "chat" }), inp = h("input", { placeholder: "Ask about an alert, agent or incident…" });
    const add = (who, t, cls = "") => log.append(h("div", { class: "msg " + cls }, h("b", {}, who + ": "), t));
    const send = async () => {
      const q = inp.value.trim(); if (!q) return; inp.value = ""; add("You", q);
      try { add("Assistant", (await api("/ai/chat", { method: "POST", body: { message: q } })).reply); }
      catch (e) { add("System", explain(e), "err"); }  // expected: POST /api/ai/chat -> { reply }
    };
    inp.addEventListener("keydown", e => e.key === "Enter" && send());
    el.replaceChildren(log, h("div", { class: "row" }, inp, h("button", { onclick: send }, "Send")));
  },

  users: el => load(el, async () => {
    // Expected backend route (not built yet): GET /api/rbac/users -> { items: [{email,name,role}] }
    const items = (await api("/rbac/users"))?.items || [];
    return table(["Email", "Name", "Role"], items.map(u => [u.email, u.name, u.role]));
  }),
};
