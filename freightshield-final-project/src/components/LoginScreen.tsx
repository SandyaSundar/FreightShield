import { useEffect, useRef, useState } from "react";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api, checkHealth, explain } from "@/api/client";
import { useAuth } from "@/store/auth";

type GoogleCredentialResponse = { credential: string };
type GoogleAccounts = {
  accounts: {
    id: {
      initialize: (options: { client_id: string; callback: (response: GoogleCredentialResponse) => void }) => void;
      renderButton: (element: HTMLElement, options: Record<string, string>) => void;
    };
  };
};

declare global {
  interface Window {
    google?: GoogleAccounts;
    L?: typeof import("leaflet");
  }
}

export function LoginScreen() {
  const buttonHost = useRef<HTMLDivElement>(null);
  const [backendState, setBackendState] = useState("Checking service status…");
  const [error, setError] = useState("");
  const [googleReady, setGoogleReady] = useState(false);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const { signIn, signUp } = useAuth();
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "";

  useEffect(() => {
    let active = true;
    void checkHealth()
      .then((health) => {
        if (!active) return;
        const integrations = health.integrations || {};
        setBackendState(`${health.status} · ${health.environment || "API"} · Wazuh manager ${integrations["wazuh_manager_configured"] ? "ready" : "not configured"} · Indexer ${integrations["wazuh_indexer_configured"] ? "ready" : "not configured"}`);
      })
      .catch((cause: unknown) => {
        if (active) {
          setBackendState("Service unavailable");
          setError(explain(cause));
        }
      });
    void api<{ google_configured: boolean; jwt_configured: boolean }>("/auth/status")
      .then((auth) => {
        if (active && (!auth.google_configured || !auth.jwt_configured)) {
          setError("Google sign-in or session security is not configured on the service.");
        }
      })
      .catch((cause: unknown) => { if (active) setError(explain(cause)); });

    if (!clientId) {
      setError("Google sign-in is not configured. Add the public Google client ID to your environment.");
      return () => { active = false; };
    }

    const setup = () => {
      if (!active) return;
      if (!window.google?.accounts.id || !buttonHost.current) return;
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: async (response) => {
          setError("");
          try {
            if (mode === "signup") await signUp(response.credential);
            else await signIn(response.credential);
          } catch (cause) {
            const message = explain(cause);
            setError(message);
            toast.error(message);
          }
        },
      });
      window.google.accounts.id.renderButton(buttonHost.current, { theme: "filled_black", size: "large", text: mode === "signup" ? "signup_with" : "signin_with", shape: "rectangular" });
      setGoogleReady(true);
    };
    const existing = document.querySelector<HTMLScriptElement>('script[src="https://accounts.google.com/gsi/client"]');
    if (existing) {
      existing.addEventListener("load", setup);
      setup();
    } else {
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.addEventListener("load", setup);
      document.head.append(script);
    }
    const interval = window.setInterval(setup, 250);
    const timeout = window.setTimeout(() => window.clearInterval(interval), 10_000);
    return () => {
      active = false;
      window.clearInterval(interval);
      window.clearTimeout(timeout);
    };
  }, [clientId, signIn, signUp, mode]);

  return (
    <main className="login-screen">
      <section className="login-panel" aria-labelledby="login-title">
        <div className="brand lockup"><span className="brand-mark"><ShieldCheck aria-hidden="true" /></span><span>FREIGHTSHIELD</span></div>
        <div className="login-rule" />
        <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
        <h1 id="login-title">FreightShield SOC</h1>
        <p className="login-copy">Harbor &amp; Finch Freight · Wazuh-integrated security operations</p>
        <div className="login-mode" role="tablist" aria-label="Sign in or create an account">
          <button type="button" role="tab" aria-selected={mode === "signin"} className={mode === "signin" ? "active" : ""} onClick={() => { setError(""); setMode("signin"); }}>Sign in</button>
          <button type="button" role="tab" aria-selected={mode === "signup"} className={mode === "signup" ? "active" : ""} onClick={() => { setError(""); setMode("signup"); }}>Create account</button>
        </div>
        {mode === "signup" && <p className="muted login-status">New accounts are created with the standard User role. Administrator and Vendor access is granted only by your security administrator.</p>}
        <div ref={buttonHost} className="google-signin" aria-label="Continue with Google" />
        {!googleReady && !error && <p className="muted login-status">Loading secure sign-in…</p>}
        {error && <p className="note err" role="alert">{error}</p>}
        <div className="service-status"><span className="status-dot" /><span><strong>BACKEND</strong>{backendState}</span></div>
        <footer>Sign in with an existing account, or create a standard User account with Google. Elevated roles are assigned by your security administrator.</footer>
        <Button className="login-access" variant="outline" type="button" onClick={() => toast.info("Access is managed by your security administrator.")}>Access information <ArrowRight aria-hidden="true" /></Button>
      </section>
      <aside className="login-side" aria-hidden="true">
        <div className="radar-grid"><div className="radar-ring ring-one" /><div className="radar-ring ring-two" /><div className="radar-cross" /><span className="radar-center"><ShieldCheck /></span><span className="radar-sweep" /></div>
        <p>FREIGHTSHIELD · LIVE OPERATIONS</p>
        <span>SECURITY FIRST. ALWAYS IN MOTION.</span>
      </aside>
    </main>
  );
}