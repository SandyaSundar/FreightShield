// App shell: Google sign-in -> backend session -> role-based navigation.
import { api, explain, checkHealth } from "./api.js";
import { can } from "./rbac.js";
import { h } from "./dom.js";
import { pages } from "./pages.js";

const { GOOGLE_CLIENT_ID } = window.APP_CONFIG;
const root = document.getElementById("root");
const NAV = [ // [route, label, required permission]
  ["dashboard", "Dashboard", "view_agents"], ["alerts", "Alerts", "view_alerts"], ["agents", "Agents", "view_agents"],
  ["incidents", "Incidents", "manage_incidents"], ["ai", "AI Assistant", "use_ai"], ["users", "User Roles", "manage_users"],
];
let user = null;

function showLogin(msg) {
  const btn = h("div", { id: "gbtn" }), err = h("div", { class: "note err" }, msg || "");
  const statusEl = h("div", { class: "note", style: "margin-top:12px;font-size:12px;" }, "Checking backend health…");
  root.replaceChildren(h("div", { class: "login" }, h("h1", {}, "🛡 FreightShield"),
    h("p", {}, "Harbor & Finch Freight · SOC Platform"), btn, err, statusEl));

  checkHealth()
    .then(data => {
      const mgr = data.integrations?.wazuh_manager_configured ? "ready" : "not configured";
      const idx = data.integrations?.wazuh_indexer_configured ? "ready" : "not configured";
      statusEl.textContent = `Backend: ${data.status} (${data.environment}) · Wazuh Manager: ${mgr} · Indexer: ${idx}`;
      statusEl.className = "note";
    })
    .catch(e => {
      statusEl.textContent = `Backend unreachable: ${explain(e)}`;
      statusEl.className = "note err";
    });

  if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.startsWith("YOUR_")) { err.textContent = "Set GOOGLE_CLIENT_ID in js/config.js."; return; }
  const init = () => {
    google.accounts.id.initialize({ client_id: GOOGLE_CLIENT_ID, callback: async r => {
      try { user = await api("/auth/google", { method: "POST", body: { credential: r.credential } }); showApp(); }
      catch (e) { err.textContent = explain(e); }   // backend verifies the Google ID token and assigns the role
    }});
    google.accounts.id.renderButton(btn, { theme: "outline", size: "large", text: "signin_with" });
  };
  window.google?.accounts ? init() : window.addEventListener("load", () => setTimeout(init, 300));
}

function showApp() {
  const allowed = NAV.filter(n => can(user, n[2]));
  const main = h("main", {});
  const apiStatus = h("span", { style: "font-size:12px;color:var(--mu);margin-right:8px;" }, "API: checking…");
  checkHealth()
    .then(data => {
      apiStatus.textContent = `● API online (${data.environment})`;
      apiStatus.style.color = "var(--pr)";
    })
    .catch(() => {
      apiStatus.textContent = "● API offline";
      apiStatus.style.color = "var(--rd)";
    });

  const render = () => {
    const id = (location.hash.slice(1) || allowed[0]?.[0]);
    const item = allowed.find(n => n[0] === id);
    document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.r === id));
    if (!item) return main.replaceChildren(h("div", { class: "note err" }, "403 – your role cannot view this page."));
    main.replaceChildren(h("h2", {}, item[1]), h("div", { id: "pg" })); pages[id](main.querySelector("#pg"));
  };
  root.replaceChildren(h("div", { class: "shell" },
    h("header", {}, h("b", {}, "🛡 FreightShield"), h("span", { class: "sp" }),
      apiStatus,
      h("span", {}, `${user.name || user.email} · `, h("em", {}, user.role)),
      h("button", { onclick: async () => { try { await api("/auth/logout", { method: "POST" }); } catch {} user = null; showLogin(); } }, "Sign out")),
    h("nav", {}, allowed.map(n => h("a", { href: "#" + n[0], "data-r": n[0] }, n[1]))), main));
  window.onhashchange = render; render();
}

(async () => {
  try { user = await api("/auth/me"); showApp(); }          // resume existing backend session
  catch (e) { showLogin(e.status === 401 ? "" : explain(e)); }
})();
