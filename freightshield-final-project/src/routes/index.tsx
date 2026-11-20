import { useEffect } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { LoginScreen } from "@/components/LoginScreen";
import { useAuth } from "@/store/auth";
import { homeFor } from "@/store/permissions";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "FreightShield SOC | Security Operations" },
      { name: "description", content: "FreightShield security operations center for Wazuh monitoring, threat response, and vendor-scoped security insights." },
      { property: "og:title", content: "FreightShield SOC | Security Operations" },
      { property: "og:description", content: "Wazuh-integrated security operations for FreightShield." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: IndexPage,
});

function IndexPage() {
  const { user, ready } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (ready && user) void navigate({ to: "/$page", params: { page: homeFor(user) }, replace: true });
  }, [navigate, ready, user]);

  return user ? <div className="session-loading" aria-live="polite">Opening your secure workspace…</div> : <LoginScreen />;
}