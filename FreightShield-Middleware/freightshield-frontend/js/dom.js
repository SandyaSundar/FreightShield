// Tiny DOM helper. Uses textContent only, so alert/agent data can never inject HTML (XSS-safe).
export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k.startsWith("on") ? el.addEventListener(k.slice(2), v) : el.setAttribute(k, v);
  for (const k of kids.flat()) if (k != null) el.append(k.nodeType ? k : document.createTextNode(String(k)));
  return el;
}
export const table = (heads, rows) =>
  h("div", { class: "scr" }, h("table", {}, h("tr", {}, heads.map(x => h("th", {}, x))),
    rows.map(r => h("tr", {}, r.map(c => h("td", {}, c))))));
