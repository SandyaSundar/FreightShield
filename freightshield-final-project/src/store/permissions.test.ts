import { describe, expect, it } from "vitest";
import { homeFor, visibleRoutes, type SessionUser } from "@/store/permissions";

const user = (role: SessionUser["role"], permissions: string[]): SessionUser => ({
  id: 7,
  email: `${role}@example.test`,
  role,
  role_label: role,
  permissions,
});

describe("role-based route visibility", () => {
  it("gives an admin both AI tools and the operations pages", () => {
    const admin = user("admin", ["wazuh:agents", "wazuh:alerts", "detections:read", "detections:write", "ir:read", "notifications:read", "ti:read", "hunt:read", "reports:read", "users:read", "audit:read", "ai:use"]);
    const visible = visibleRoutes(admin).map((route) => route.id);
    expect(visible).toContain("ai");
    expect(visible).toContain("email");
    expect(visible).toContain("users");
    expect(visible).not.toContain("logistics");
  });

  it("shows a vendor only vendor pages and the pickup simulation", () => {
    const vendor = user("vendor", ["vendor:agents", "vendor:alerts", "vendor:detections", "vendor:responses", "vendor:threatintel", "vendor:reports", "vendor:notifications", "vendor:hunt"]);
    const visible = visibleRoutes(vendor).map((route) => route.id);
    expect(visible).toEqual(["profile", "vendor-agents", "vendor-alerts", "vendor-detections", "vendor-response", "vendor-notifications", "vendor-threatintel", "vendor-hunting", "vendor-reports", "logistics"]);
    expect(homeFor(vendor)).toBe("logistics");
  });

  it("shows a user only profile and delivery simulation", () => {
    const regular = user("user", []);
    expect(visibleRoutes(regular).map((route) => route.id)).toEqual(["profile", "logistics"]);
    expect(homeFor(regular)).toBe("logistics");
  });
});