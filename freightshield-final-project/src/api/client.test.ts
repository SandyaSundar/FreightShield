import { afterEach, describe, expect, it, vi } from "vitest";
import { api, clearCsrf, setApiQueryClient } from "@/api/client";

describe("FreightShield API client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearCsrf();
    setApiQueryClient(null);
  });

  it("sends the CSRF token from the auth response on state-changing requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "csrf-value" }), { status: 200, headers: { "Content-Type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } }));

    await api("/auth/google", { method: "POST", body: { credential: "google-id-token" } });
    await api("/detections/run", { method: "POST" });

    const secondHeaders = new Headers(fetchMock.mock.calls[1]?.[1]?.headers);
    expect(secondHeaders.get("X-CSRF-Token")).toBe("csrf-value");
  });

  it("announces a protected 401 so the app returns to sign-in", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "Session expired" }), { status: 401, headers: { "Content-Type": "application/json" } }),
    );
    const expired = vi.fn();
    window.addEventListener("session-expired", expired);

    await expect(api("/wazuh/manager/agents")).rejects.toMatchObject({ status: 401 });

    expect(expired).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledOnce();
    window.removeEventListener("session-expired", expired);
  });
});

describe("Google self-sign-up client call", () => {
  afterEach(() => { vi.restoreAllMocks(); clearCsrf(); setApiQueryClient(null); });

  it("posts only the Google credential to /auth/google/signup and keeps the CSRF token in memory", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ id: 5, email: "n@x.co", role: "user", permissions: [], csrf_token: "c1" }), { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    const session = await api<{ role: string }>("/auth/google/signup", { method: "POST", body: { credential: "google-id-token" } });
    expect(session.role).toBe("user");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith("/auth/google/signup")).toBe(true);
    expect(init.credentials).toBe("include");
    expect(JSON.parse(init.body as string)).toEqual({ credential: "google-id-token" });
  });

  it("surfaces a signup conflict without announcing a session expiry", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "An account with this Google email already exists. Use Sign in instead." }), { status: 409, headers: { "Content-Type": "application/json" } }),
    );
    const expired = vi.fn();
    window.addEventListener("session-expired", expired);
    await expect(api("/auth/google/signup", { method: "POST", body: { credential: "x".repeat(30) } })).rejects.toMatchObject({ status: 409 });
    expect(expired).not.toHaveBeenCalled();
    window.removeEventListener("session-expired", expired);
  });
});
