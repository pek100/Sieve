/**
 * Mock engine: answers `probe` with one of the examples of the wire fixture
 * (src/data/fixtures/engine-probe-v1.json), so the browser, tests and e2e
 * show exactly the shapes Rust produces. Query string `?engine=<scenario>`,
 * default `missing` (a browser has no engine). `error` makes every probe
 * fail, as an unreadable service manager would.
 */
import fixture from "./fixtures/engine-probe-v1.json";
import type { EngineSource } from "./engine-source";
import { parseEngineProbe } from "./protocol";

export const ENGINE_SCENARIOS = ["missing", "stopped", "starting", "idle", "incompatible", "refused", "unreachable", "error"] as const;
export type EngineScenario = (typeof ENGINE_SCENARIOS)[number];

export const MOCK_ENGINE_ERROR = "service manager: Access is denied. (os error 5)";

export function createMockEngine(scenario: EngineScenario = "missing"): EngineSource {
  return {
    kind: "mock",
    probe: async () => {
      if (scenario === "error") throw new Error(MOCK_ENGINE_ERROR);
      return parseEngineProbe(fixture.examples[scenario]);
    },
  };
}
