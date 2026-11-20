export type Role = "admin" | "user" | "vendor";
export type SessionUser = {
  id: number | string;
  email: string;
  name?: string;
  role: Role;
  role_label: string;
  permissions: string[];
};

export type RouteDefinition = {
  id: string;
  label: string;
  permission: string | null;
  group: string;
};

export const ROUTES: RouteDefinition[] = [
  { id: "dashboard", label: "Operations overview", permission: "wazuh:agents", group: "Operations" },
  { id: "alerts", label: "Wazuh alerts", permission: "wazuh:alerts", group: "Operations" },
  { id: "agents", label: "Wazuh agents", permission: "wazuh:agents", group: "Operations" },
  { id: "detections", label: "Detections", permission: "detections:read", group: "Detection & response" },
  { id: "incidents", label: "Incidents", permission: "detections:read", group: "Detection & response" },
  { id: "rules", label: "Detection rules", permission: "detections:write", group: "Detection & response" },
  { id: "response", label: "Incident response", permission: "ir:read", group: "Detection & response" },
  { id: "notifications", label: "Notifications", permission: "notifications:read", group: "Insights" },
  { id: "threatintel", label: "Threat intelligence", permission: "ti:read", group: "Insights" },
  { id: "hunting", label: "Threat hunting", permission: "hunt:read", group: "Insights" },
  { id: "reports", label: "Reports & analytics", permission: "reports:read", group: "Insights" },
  { id: "ai", label: "AI SOC Investigator", permission: "ai:use", group: "Admin AI tools" },
  { id: "email", label: "AI Email Router", permission: "ai:use", group: "Admin AI tools" },
  { id: "users", label: "Users & roles", permission: "users:read", group: "Administration" },
  { id: "audit", label: "Audit trail", permission: "audit:read", group: "Administration" },
  { id: "profile", label: "My profile", permission: null, group: "Account" },
  { id: "vendor-agents", label: "My agents", permission: "vendor:agents", group: "My operations" },
  { id: "vendor-alerts", label: "My alerts", permission: "vendor:alerts", group: "My operations" },
  { id: "vendor-detections", label: "My detections", permission: "vendor:detections", group: "My operations" },
  { id: "vendor-response", label: "My responses", permission: "vendor:responses", group: "My operations" },
  { id: "vendor-notifications", label: "My notifications", permission: "vendor:notifications", group: "My insights" },
  { id: "vendor-threatintel", label: "My threat intelligence", permission: "vendor:threatintel", group: "My insights" },
  { id: "vendor-hunting", label: "My threat hunting", permission: "vendor:hunt", group: "My insights" },
  { id: "vendor-reports", label: "My reports", permission: "vendor:reports", group: "My insights" },
];

export function can(user: SessionUser | null, permission: string) {
  return Boolean(user?.permissions.includes(permission));
}

export function visibleRoutes(user: SessionUser | null) {
  if (!user) return [];
  const routes = ROUTES.filter((route) => route.id === "profile" || (route.permission && can(user, route.permission)));
  if (user.role === "user" || user.role === "vendor") {
    routes.push({
      id: "logistics",
      label: user.role === "vendor" ? "Pickup map (simulation)" : "Delivery map (simulation)",
      permission: null,
      group: "Logistics simulation",
    });
  }
  return routes;
}

export function homeFor(user: SessionUser) {
  if (user.role === "user" || user.role === "vendor") return "logistics";
  return visibleRoutes(user)[0]?.id || "profile";
}