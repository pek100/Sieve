import { defineConfig, devices } from "@playwright/test";

// e2e runs against the static export in out/ (run `pnpm e2e`, which builds first).
// Chromium only, GPU disabled. Screenshots of every spec go to test-results/screens/.
const PORT = 3417;

export default defineConfig({
  testDir: "tests/e2e",
  outputDir: "test-results/artifacts",
  fullyParallel: true,
  workers: 2,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "off",
    launchOptions: { args: ["--disable-gpu"] },
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 800 } } },
    { name: "mobile", use: { ...devices["Desktop Chrome"], viewport: { width: 375, height: 812 }, hasTouch: true } },
  ],
  webServer: {
    command: "node scripts/serve-out.mjs",
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: false,
    timeout: 30_000,
    env: { PORT: String(PORT) },
  },
});
