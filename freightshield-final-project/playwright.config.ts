import { defineConfig, devices } from "@playwright/test";
import { existsSync } from "node:fs";

export default defineConfig({
  globalSetup: "./tests/e2e/global-setup.ts",
  testDir: "./tests/e2e",
  fullyParallel: false,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:5174",
    trace: "retain-on-failure",
    launchOptions: {
      ...(existsSync("/bin/chromium") ? { executablePath: "/bin/chromium", args: ["--no-sandbox"] } : {}),
    },
    ...devices["Desktop Chrome"],
  },
  webServer: [
    {
      command: "python -m uvicorn app.main:app --host 127.0.0.1 --port 8010",
      cwd: "backend",
      url: "http://127.0.0.1:8010/api/health",
      reuseExistingServer: false,
      env: {
        AUTH_JWT_SECRET: "test-only-freightshield-e2e-secret-32",
        DATABASE_PATH: "/tmp/freightshield-e2e.sqlite3",
        CORS_ALLOWED_ORIGINS: "http://127.0.0.1:5174",
      },
      timeout: 120_000,
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 5174",
      url: "http://127.0.0.1:5174",
      reuseExistingServer: false,
      env: {
        VITE_API_BASE_URL: "http://127.0.0.1:8010/api",
      },
      timeout: 120_000,
    },
  ],
});