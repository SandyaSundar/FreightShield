import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const sessions = JSON.parse(readFileSync("/tmp/freightshield-playwright/sessions.json", "utf8")) as Record<string, string>;

async function useRole(page: import("@playwright/test").Page, role: string) {
  await page.context().addCookies([{ name: "fs_session", value: sessions[role] || "", domain: "127.0.0.1", path: "/api", httpOnly: true, sameSite: "Lax" }]);
  await page.goto(role === "admin" ? "/dashboard" : "/logistics");
}

test("opens sign-in and reaches a locally started FastAPI service", async ({ page, request }) => {
  const health = await request.get("http://127.0.0.1:8010/api/health");
  expect(health.ok(), `${health.status()} ${await health.text()}`).toBeTruthy();

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "FreightShield SOC" })).toBeVisible();
  await expect(page.locator(".service-status")).toContainText(/manager/);
});

test("admin sees both AI tools and no logistics page", async ({ page }) => {
  await useRole(page, "admin");
  const apiResponse = await page.request.get("http://127.0.0.1:8010/api/users?limit=10");
  expect(apiResponse.ok()).toBeTruthy();
  await expect(page.getByRole("heading", { name: "Operations overview" })).toBeVisible({ timeout: 12_000 });
  await expect(page.getByRole("banner").getByRole("button", { name: "AI SOC Investigator" })).toBeVisible();
  await expect(page.getByRole("banner").getByRole("button", { name: "AI Email Router" })).toBeVisible();
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation.getByRole("button", { name: "AI SOC Investigator" })).toBeVisible();
  await expect(navigation.getByRole("button", { name: /Pickup map|Delivery map/ })).toHaveCount(0);
});

test("vendor sees vendor-scoped pages and no administrator or general security pages", async ({ page }) => {
  await useRole(page, "vendor");
  const adminEndpoint = await page.request.get("http://127.0.0.1:8010/api/users?limit=10");
  expect(adminEndpoint.status()).toBe(403);
  await expect(page.getByRole("heading", { name: "Pickup map (simulation)" })).toBeVisible({ timeout: 12_000 });
  await expect(page.getByRole("region", { name: "Simulated route on OpenStreetMap" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Start simulation/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "My agents" })).toBeVisible();
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation.getByRole("button", { name: "Users & roles" })).toHaveCount(0);
  await expect(navigation.getByRole("button", { name: "Wazuh agents" })).toHaveCount(0);
  await expect(navigation.getByRole("button", { name: /AI SOC Investigator/ })).toHaveCount(0);

  await expect(page.locator(".shipping-status-panel")).toContainText(/remaining/, { timeout: 15_000 });
  await page.getByRole("button", { name: /Start simulation/ }).click();
  await expect(page.getByRole("button", { name: /Pause/ })).toBeVisible();
  await expect(page.locator(".shipping-status-panel")).toContainText("Arrived at vendor", { timeout: 5_000 });
  await page.getByRole("button", { name: /Pause/ }).click();
  await expect(page.getByRole("button", { name: /Resume/ })).toBeVisible();
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.locator(".shipping-status-panel")).toContainText("Pickup scheduled");
});

test("user sees only profile and delivery simulation", async ({ page }) => {
  await useRole(page, "user");
  const adminEndpoint = await page.request.get("http://127.0.0.1:8010/api/users?limit=10");
  expect(adminEndpoint.status()).toBe(403);
  await expect(page.getByRole("heading", { name: "Delivery map (simulation)" })).toBeVisible({ timeout: 12_000 });
  await expect(page.getByRole("region", { name: "Simulated route on OpenStreetMap" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Start simulation/ })).toBeVisible();
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation.getByRole("button", { name: "My profile" })).toBeVisible();
  await expect(navigation.getByRole("button", { name: /Wazuh|Users & roles|AI SOC|My agents/ })).toHaveCount(0);
  await expect(page.locator(".shipping-status-panel")).toContainText(/remaining/, { timeout: 15_000 });
  await page.getByRole("button", { name: /Start simulation/ }).click();
  await expect(page.getByRole("button", { name: /Pause/ })).toBeVisible();
  await expect(page.locator(".shipping-status-panel")).toContainText("In transit", { timeout: 5_000 });
  await page.getByRole("button", { name: /Pause/ }).click();
  await expect(page.getByRole("button", { name: /Resume/ })).toBeVisible();
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.locator(".shipping-status-panel")).toContainText("Order confirmed");
});