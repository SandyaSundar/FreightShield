import type { QueryClient } from "@tanstack/react-query";

export type HttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";
export type ApiOptions = { method?: HttpMethod; body?: unknown; timeout?: number; signal?: AbortSignal };

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, body: unknown) {
    const detail = typeof body === "object" && body !== null && "detail" in body
      ? (body as { detail?: unknown }).detail
      : undefined;
    super(typeof detail === "string" ? detail : `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

let csrfToken: string | null = null;
let queryClient: QueryClient | null = null;
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api").replace(/\/$/, "");
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function setApiQueryClient(client: QueryClient | null) {
  queryClient = client;
}

export function clearCsrf() {
  csrfToken = null;
}

function cookieCsrf() {
  if (typeof document === "undefined") return null;
  const match = document.cookie.split(";").map((entry) => entry.trim()).find((entry) => entry.startsWith("fs_csrf="));
  if (!match) return null;
  try {
    return decodeURIComponent(match.slice("fs_csrf=".length));
  } catch {
    return match.slice("fs_csrf=".length);
  }
}

async function request<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const method = (options.method || "GET").toUpperCase() as HttpMethod;
  const unsafe = !SAFE_METHODS.has(method);
  if (unsafe && !csrfToken) csrfToken = cookieCsrf();

  const headers = new Headers();
  if (options.body !== undefined) headers.set("Content-Type", "application/json");
  if (unsafe && csrfToken) headers.set("X-CSRF-Token", csrfToken);

  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  const timeout = options.timeout ?? (path.startsWith("/ai/") ? 180_000 : 20_000);
  const timer = setTimeout(abort, timeout);
  let response: Response;
  try {
    const init: RequestInit = {
      method,
      credentials: "include",
      headers,
      signal: controller.signal,
    };
    if (options.body !== undefined) init.body = JSON.stringify(options.body);
    response = await fetch(`${API_BASE}${path}`, init);
  } catch (error) {
    const timedOut = error instanceof DOMException && error.name === "AbortError";
    throw new ApiError(0, { detail: timedOut ? "The request timed out." : "Cannot reach the backend. Check that it is running and configured." });
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }

  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/")) {
      if (typeof window !== "undefined") window.dispatchEvent(new Event("session-expired"));
    }
    throw new ApiError(response.status, data);
  }

  if (typeof data === "object" && data !== null && "csrf_token" in data && typeof data.csrf_token === "string") {
    csrfToken = data.csrf_token;
  } else if (unsafe) {
    csrfToken = cookieCsrf() || csrfToken;
  }
  return data as T;
}

export function api<T = Record<string, unknown>>(path: string, options: ApiOptions = {}): Promise<T> {
  if (!queryClient || (options.method && !SAFE_METHODS.has(options.method))) return request<T>(path, options);
  return queryClient.fetchQuery({
    queryKey: ["api", path],
    queryFn: ({ signal }) => request<T>(path, { ...options, signal }),
    staleTime: 10_000,
  });
}

export function explain(error: unknown) {
  const status = error instanceof ApiError ? error.status : 0;
  const detail = error instanceof ApiError && typeof error.body === "object" && error.body !== null && "detail" in error.body
    ? error.body.detail
    : "";
  const notes: Record<number, string> = {
    401: "Please sign in.",
    403: "Your account cannot access this operation.",
    404: "The requested record or endpoint was not found.",
    413: "The request is too large.",
    429: "Too many requests. Wait a moment and retry.",
    501: "This feature is not implemented by the service.",
    503: "A required service is unavailable or not configured.",
  };
  const message = error instanceof Error ? error.message : "Unexpected error";
  const parsedDetail = Array.isArray(detail)
    ? detail.map((item) => typeof item === "object" && item !== null && "msg" in item ? String(item.msg) : "").filter(Boolean).join("; ")
    : typeof detail === "string" ? detail : "";
  return notes[status] ? [notes[status], parsedDetail].filter(Boolean).join(" ") : message;
}

export async function download(path: string) {
  if (!csrfToken) csrfToken = cookieCsrf();
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: csrfToken ? { "X-CSRF-Token": csrfToken } : {},
  });
  if (response.status === 401) window.dispatchEvent(new Event("session-expired"));
  if (!response.ok) throw new ApiError(response.status, await response.json().catch(() => null));
  const filename = /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "")?.[1] || "report";
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return filename;
}

export function checkHealth() {
  return api<{ status: string; environment?: string; integrations?: Record<string, boolean> }>("/health");
}