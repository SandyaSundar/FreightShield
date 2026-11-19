// Thin API client. Session lives in an httpOnly cookie set by the backend, so JS never handles tokens.
const API_BASE_URL = (window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL) || "http://localhost:8000/api";

export class ApiError extends Error {
  constructor(status, body) { super(body?.detail || `HTTP ${status}`); this.status = status; this.body = body; }
}

export async function api(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(API_BASE_URL + path, {
      method, credentials: "include",
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch { throw new ApiError(0, { detail: "Cannot reach the backend. Is it running and is CORS configured?" }); }
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

export async function checkHealth() {
  return await api("/health");
}

// Human-readable message per failure class; no data is ever invented.
export function explain(e) {
  const m = { 401: "Please sign in.", 403: "Your role is not allowed to do this.",
    404: "This backend endpoint does not exist yet.", 501: "Not implemented on the backend yet.",
    503: "Backend service not configured or unreachable (check Wazuh settings)." };
  return m[e.status] ? `${m[e.status]} ${e.body?.detail || ""}`.trim() : (e.message || "Unexpected error");
}
