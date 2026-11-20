// Logistics simulation on a REAL OpenStreetMap (Leaflet). The backend has no carrier API, so the shipment itself is a labelled
// simulation; the map tiles and road geometry (OSRM, OpenStreetMap-based, public demo server) are real. Falls back to a straight line if routing is unreachable.
import { h, note } from "./dom.js";

const SITES = { // real Bengaluru locations
  depot: { name: "FreightShield Depot (Majestic)", c: [12.9767, 77.5713] },
  customer: { name: "Customer drop (Hebbal)", c: [13.0358, 77.5970] },
  vendor: { name: "Vendor pickup (Peenya Industrial Area)", c: [13.0285, 77.5197] },
};
const STEPS = {
  user: ["Order confirmed", "Picked up from depot", "In transit", "Out for delivery", "Delivered"],
  vendor: ["Pickup scheduled", "Driver en route", "Arrived at vendor", "Loaded & departed", "Delivered to depot"],
};
const haversine = (a, b) => { const R = 6371e3, r = x => x * Math.PI / 180, dLat = r(b[0] - a[0]), dLng = r(b[1] - a[1]);
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(r(a[0])) * Math.cos(r(b[0])) * Math.sin(dLng / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(s)); };

async function roadRoute(from, to) {
  try { const ctl = new AbortController(); setTimeout(() => ctl.abort(), 8000);
    const r = await fetch(`https://router.project-osrm.org/route/v1/driving/${from[1]},${from[0]};${to[1]},${to[0]}?overview=full&geometries=geojson`, { signal: ctl.signal });
    const j = await r.json(); if (j.code !== "Ok") throw 0;
    return { pts: j.routes[0].geometry.coordinates.map(([lng, lat]) => [lat, lng]), road: true };
  } catch { return { pts: [from, to], road: false }; }
}

export function logisticsPage(el, user) {
  const vendor = user.role === "vendor", labels = STEPS[vendor ? "vendor" : "user"];
  const origin = vendor ? SITES.depot : SITES.depot, dest = vendor ? SITES.vendor : SITES.customer;
  const from = vendor ? SITES.depot.c : SITES.depot.c, to = vendor ? SITES.vendor.c : SITES.customer.c;
  const ref = `FS-SIM-${vendor ? "PU" : "DL"}-${String(user.id ?? 0).padStart(4, "0")}`;
  let route = null, idx = 0, playing = false, speed = 1, timer = null, leg = 0, vehicle = null, trail = null, map = null;
  const mapEl = h("div", { class: "shipping-map", role: "region", "aria-label": "Simulated route on OpenStreetMap" });
  const statusEl = h("div", {}), bar = h("i"), progress = h("div", { class: "shipping-progress" }), tl = h("div", {});
  const play = h("button", {}, "▶ Start simulation"), reset = h("button", { class: "sec" }, "Reset");
  const spd = h("select", { "aria-label": "Simulation speed" }, [1, 2, 4, 8].map(v => h("option", { value: v }, `${v}× speed`)));
  const eta = h("small", {});

  const total = () => route ? route.pts.length - 1 : 1;
  const stage = () => { const p = idx / total(); return p === 0 ? (playing ? 1 : 0) : p >= 1 ? 4 : p < .35 ? 2 : p < .8 ? 3 : 3; };
  const distLeft = () => { if (!route) return 0; let d = 0; for (let i = Math.floor(idx); i < route.pts.length - 1; i++) d += haversine(route.pts[i], route.pts[i + 1]); return d; };
  const paint = () => {
    const done = idx >= total(), s = done ? labels.length - 1 : stage(), pct = Math.round(100 * idx / total());
    const kmh = 30 * speed, left = distLeft(), mins = left / 1000 / 30 * 60;
    statusEl.replaceChildren(h("div", { class: "shipping-current-label" }, vendor ? "PICKUP STATUS" : "DELIVERY STATUS"), h("strong", {}, labels[s]),
      h("span", {}, done ? "Complete" : `${(left / 1000).toFixed(1)} km remaining · simulated ETA ${Math.max(1, Math.round(mins))} min (real-time)`), eta);
    eta.textContent = route ? (route.road ? "Road geometry: OpenStreetMap / OSRM" : "Routing service unreachable — straight-line path") : "";
    bar.style.width = pct + "%";
    progress.replaceChildren(...labels.map((l, i) => h("div", { class: `shipping-step${i < s || done ? " complete" : ""}${i === s && !done ? " current" : ""}` }, h("span", { class: "step-index" }, i < s || done ? "✓" : i + 1), l)));
    tl.replaceChildren(...labels.map((l, i) => h("div", { class: `timeline-event${i === s ? " current" : ""}` }, h("span", { class: "timeline-mark" }, i < s ? "✓" : i + 1), h("div", {}, h("strong", {}, l), h("small", {}, i < s ? "Completed" : i === s ? "Current" : "Pending")))));
    play.textContent = done ? "✓ Complete" : playing ? "❚❚ Pause" : idx ? "▶ Resume" : "▶ Start simulation"; play.disabled = done;
  };
  const place = () => { if (!vehicle || !route) return; const i = Math.min(Math.floor(idx), total()); vehicle.setLatLng(route.pts[i]); trail.setLatLngs(route.pts.slice(0, i + 1));
    if (map && playing) map.panTo(route.pts[i], { animate: true, duration: .4 }); };
  const tick = () => { if (!route) return; // ~30 km/h simulated truck; advance by metres travelled this 400ms tick
    let metres = 30 / 3.6 * 0.4 * speed * 12; // 12× compression so a trip is watchable
    while (metres > 0 && idx < total()) { const i = Math.floor(idx), d = haversine(route.pts[i], route.pts[i + 1]) || 1; const frac = idx - i, rem = d * (1 - frac);
      if (metres >= rem) { idx = i + 1; metres -= rem; } else { idx = i + frac + metres / d; metres = 0; } }
    if (idx >= total()) { idx = total(); playing = false; clearInterval(timer); }
    place(); paint(); };
  play.addEventListener("click", () => { if (!route) return; playing = !playing; clearInterval(timer); if (playing) timer = setInterval(tick, 400); paint(); });
  reset.addEventListener("click", () => { playing = false; clearInterval(timer); idx = 0; place(); paint(); });
  spd.addEventListener("change", () => { speed = +spd.value; });

  el.replaceChildren(h("div", { class: "simulation-banner" }, h("strong", {}, "SIMULATION"), `A simulated ${vendor ? "pickup" : "delivery"} on a real OpenStreetMap. The backend exposes no carrier data, so the shipment is simulated; the map and road geometry are real.`),
    h("div", { class: "shipping-layout" },
      h("section", { class: "shipping-main" },
        h("div", { class: "shipping-panel-heading" }, h("div", {}, h("span", { class: "shipping-kicker" }, `REFERENCE · ${ref}`), h("h3", {}, vendor ? "Vendor pickup" : "Package delivery")), h("div", { class: "row" }, spd, play, reset)),
        h("div", { class: "shipping-status-panel" }, statusEl), h("div", { class: "bar" }, bar), progress, mapEl,
        h("p", { class: "map-attribution" }, "Map data © OpenStreetMap contributors · Routing: OSRM demo server · Leaflet")),
      h("aside", { class: "shipping-side" }, h("div", { class: "shipping-side-head" }, "ROUTE ACTIVITY"), tl,
        h("div", { class: "shipping-details" }, h("span", {}, "REFERENCE"), h("strong", {}, ref), h("span", {}, "FROM"), h("strong", {}, vendor ? SITES.depot.name : SITES.depot.name),
          h("span", {}, "TO"), h("strong", {}, dest.name)))));
  paint();
  if (!window.L) { mapEl.replaceChildren(note("err", "The map library failed to load. Refresh the page.")); return; }
  const L = window.L;
  map = L.map(mapEl, { scrollWheelZoom: true }).setView(from, 12);
  L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { maxZoom: 19, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap contributors</a>' }).addTo(map);
  const pin = (c, cls, n, txt) => L.marker(c, { icon: L.divIcon({ className: `shipping-map-icon ${cls}`, html: `<span>${n}</span>`, iconSize: [30, 30], iconAnchor: [15, 15] }) }).bindPopup(txt).addTo(map);
  pin(from, "pickup", "A", origin.name); pin(to, "destination", "B", dest.name);
  roadRoute(from, to).then(r => { route = r; L.polyline(r.pts, { color: "#60a5fa", weight: 5, opacity: .55 }).addTo(map);
    trail = L.polyline([r.pts[0]], { color: "#2dd4bf", weight: 5 }).addTo(map);
    vehicle = L.marker(r.pts[0], { icon: L.divIcon({ className: "shipping-map-icon vehicle", html: "<span>🚚</span>", iconSize: [34, 34], iconAnchor: [17, 17] }), zIndexOffset: 1000 }).addTo(map);
    map.fitBounds(L.polyline(r.pts).getBounds(), { padding: [30, 30] }); paint(); });
  requestAnimationFrame(() => map.invalidateSize());
  return () => { clearInterval(timer); map.remove(); };
}
