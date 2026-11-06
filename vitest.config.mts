import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}", "tests/laws/**/*.test.ts"],
    exclude: ["tests/e2e/**", "node_modules/**"],
    css: false,
    restoreMocks: true,
    // Component tests drive Radix and sonner through jsdom; on a shared, loaded machine the 5 s
    // default timed out apps tests that pass alone in about 2 s each (wave 2, 2026-10-17).
    testTimeout: 20_000,
    // The default of one worker per logical core starved random engine-card tests past that
    // timeout (240 ms alone, 26 s in a full run, 2026-11-06). Eight take the same 40 s, reliably.
    maxWorkers: 8,
  },
});
