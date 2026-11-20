import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, clearCsrf } from "@/api/client";
import type { SessionUser } from "@/store/permissions";

type AuthContextValue = {
  user: SessionUser | null;
  ready: boolean;
  signIn: (credential: string) => Promise<void>;
  signUp: (credential: string) => Promise<void>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;
    const loadSession = async () => {
      try {
        const session = await api<SessionUser & { csrf_token?: string }>("/auth/me");
        if (active) setUser(session);
      } catch {
        if (active) setUser(null);
      } finally {
        if (active) setReady(true);
      }
    };
    const expire = () => {
      clearCsrf();
      setUser(null);
    };
    window.addEventListener("session-expired", expire);
    void loadSession();
    return () => {
      active = false;
      window.removeEventListener("session-expired", expire);
    };
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    ready,
    signIn: async (credential) => {
      const session = await api<SessionUser & { csrf_token?: string }>("/auth/google", {
        method: "POST",
        body: { credential },
      });
      setUser(session);
    },
    // Self-registration: only the Google ID token is sent; the server verifies it and assigns the standard User role.
    signUp: async (credential) => {
      const session = await api<SessionUser & { csrf_token?: string }>("/auth/google/signup", {
        method: "POST",
        body: { credential },
      });
      setUser(session);
    },
    signOut: async () => {
      try {
        await api("/auth/logout", { method: "POST" });
      } finally {
        clearCsrf();
        setUser(null);
      }
    },
  }), [user, ready]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}