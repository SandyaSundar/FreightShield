// DOM helpers + shared UI primitives. textContent only, so backend data can never inject HTML (XSS-safe).
export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) { if (v === false || v == null) continue; k.startsWith("on") ? el.addEventListener(k.slice(2), v) : el.setAttribute(k, v === true ? "" : v); }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k.nodeType ? k : document.createTextNode(String(k)));
  return el;
}
export const table = (heads, rows, { onRow } = {}) =>
  h("div", { class: "scr" }, h("table", {}, h("thead", {}, h("tr", {}, heads.map(x => h("th", {}, x)))),
    h("tbody", {}, rows.map((r, i) => { const tr = h("tr", onRow ? { class: "click", tabindex: "0" } : {}, r.map(c => h("td", {}, c)));
      if (onRow) { tr.addEventListener("click", ev => { if (!ev.target.closest("button,select,a,input")) onRow(i); }); tr.addEventListener("keydown", ev => ev.key === "Enter" && onRow(i)); } return tr; }))));

export const note = (cls, msg) => h("div", { class: "note " + cls }, msg);
export const skeleton = (n = 4) => h("div", {}, h("div", { class: "skel-grid" }, [...Array(4)].map(() => h("div", { class: "skel" }))), [...Array(n)].map(() => h("div", { class: "skel" })));
export const kp = (label, value, tone = "") => h("div", { class: "kp " + tone }, h("b", {}, value), h("small", {}, label));
export const when = ts => { const d = new Date(ts); return isNaN(d) ? (ts ?? "-") : d.toLocaleString(); };
export const badge = (text, cls = "") => h("span", { class: `badge ${cls}` }, text);
export const sevBadge = s => badge(s, "sev-" + s);
export const statusBadge = s => badge(String(s).replace("_", " "), "st-" + s);

// ---- toasts
let toastBox;
export function toast(msg, kind = "") {
  toastBox ||= document.body.appendChild(h("div", { class: "toasts", "aria-live": "polite" }));
  const t = h("div", { class: "toast " + kind, role: "status" }, msg); toastBox.append(t);
  while (toastBox.children.length > 5) toastBox.firstChild.remove();
  setTimeout(() => t.remove(), kind === "err" || kind === "critical" ? 9000 : 5000);
}

// ---- slide-over drawer (details, AI agents)
export function drawer(title, content, { onClose } = {}) {
  const back = h("div", { class: "back" }), dr = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => { back.classList.remove("open"); dr.classList.remove("open"); document.removeEventListener("keydown", esc); setTimeout(() => { back.remove(); dr.remove(); }, 250); onClose?.(); };
  const esc = e => e.key === "Escape" && close();
  dr.append(h("div", { class: "drawer-head" }, h("h3", {}, title), h("button", { class: "sec icon-button", "aria-label": "Close", onclick: close }, "✕")), h("div", { class: "drawer-body" }, content));
  back.addEventListener("click", close); document.addEventListener("keydown", esc); document.body.append(back, dr);
  requestAnimationFrame(() => { back.classList.add("open"); dr.classList.add("open"); });
  return { close, el: dr };
}

// ---- inline SVG charts
const NS = "http://www.w3.org/2000/svg";
export const svg = (tag, attrs = {}, ...kids) => { const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k))); return e; };
export const SEV_COLOR = { low: "var(--green)", medium: "var(--amber)", high: "var(--ops-orange)", critical: "var(--rd)" };
export const STATUS_COLOR = { active: "var(--green)", disconnected: "var(--ops-orange)", never_connected: "var(--rd)", pending: "var(--amber)" };
const PALETTE = ["var(--pr)", "var(--blue)", "var(--violet)", "var(--amber)", "var(--ops-orange)", "var(--rd)", "var(--green)"];

export function donut(title, data, colors = {}) {
  const total = data.reduce((s, d) => s + d[1], 0), R = 46, C = 2 * Math.PI * R; let off = 0;
  const el = svg("svg", { viewBox: "0 0 120 120", role: "img", "aria-label": title }, svg("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: "var(--bd)", "stroke-width": 14 }));
  data.forEach(([k, v], i) => { if (!v) return; const len = C * v / total;
    el.append(svg("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: colors[k] || PALETTE[i % PALETTE.length], "stroke-width": 14, "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -off, transform: "rotate(-90 60 60)" }, svg("title", {}, `${k}: ${v}`))); off += len; });
  el.append(svg("text", { x: 60, y: 66, "text-anchor": "middle", fill: "var(--tx)", "font-size": 20, "font-weight": 700 }, total));
  return h("div", { class: "card" }, h("h3", {}, title), h("div", { class: "donut-wrap" }, el,
    h("div", { class: "legend", style: "flex-direction:column;gap:5px" }, data.map(([k, v], i) => h("span", {}, h("i", { style: `background:${colors[k] || PALETTE[i % PALETTE.length]}` }), `${String(k).replace("_", " ")} · ${v}`)))));
}
export function barChart(title, data, colors = {}) {
  const max = Math.max(1, ...data.map(d => d[1])), rowH = 24, W = 420;
  const el = svg("svg", { viewBox: `0 0 ${W} ${Math.max(1, data.length) * rowH + 8}`, class: "chart", role: "img", "aria-label": title });
  if (!data.length) el.append(svg("text", { x: 4, y: 18, fill: "currentColor" }, "No data in this period"));
  data.forEach(([k, v], i) => { const y = i * rowH + 4, w = (W - 150) * v / max;
    el.append(svg("text", { x: 0, y: y + 14, fill: "currentColor", "font-size": 11 }, String(k).slice(0, 18)),
      svg("rect", { x: 110, y, width: Math.max(w, v ? 2 : 0), height: 16, fill: colors[k] || "var(--pr)", rx: 3 }),
      svg("text", { x: 115 + w, y: y + 13, fill: "currentColor", "font-size": 11 }, v)); });
  return h("div", { class: "card" }, h("h3", {}, title), el);
}
export function trendChart(title, days) {
  const W = 600, Hh = 160, n = days.length, max = Math.max(1, ...days.map(d => d.total)), bw = Math.max(2, (W - 30) / Math.max(n, 1) - 2);
  const el = svg("svg", { viewBox: `0 0 ${W} ${Hh + 24}`, class: "chart", role: "img", "aria-label": title });
  el.append(svg("text", { x: 0, y: 10, fill: "currentColor", "font-size": 10 }, max), svg("line", { x1: 24, x2: W, y1: Hh, y2: Hh, stroke: "currentColor", opacity: .4 }));
  days.forEach((d, i) => { let y = Hh; const x = 26 + i * (bw + 2);
    for (const s of ["low", "medium", "high", "critical"]) { const hh = (Hh - 14) * d[s] / max; if (!hh) continue; y -= hh;
      el.append(svg("rect", { x, y, width: bw, height: hh, fill: SEV_COLOR[s] }, svg("title", {}, `${d.date} ${s}: ${d[s]}`))); } });
  if (n) el.append(svg("text", { x: 26, y: Hh + 16, fill: "currentColor", "font-size": 10 }, days[0].date), svg("text", { x: W, y: Hh + 16, "text-anchor": "end", fill: "currentColor", "font-size": 10 }, days[n - 1].date));
  return h("div", { class: "card wide" }, h("h3", {}, title), el, h("div", { class: "legend" }, Object.entries(SEV_COLOR).map(([k, c]) => h("span", {}, h("i", { style: `background:${c}` }), k))));
}
