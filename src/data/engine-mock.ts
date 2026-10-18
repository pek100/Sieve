/**
 * Mock engine: answers `probe` with one of the examples of the wire fixture
 * (src/data/fixtures/engine-probe-v2.json), so the browser, tests and e2e
 * show exactly the shapes Rust produces. Query string `?engine=<scenario>`,
 * default `missing` (a browser has no engine). `error` makes every probe
 * fail, as an unreadable service manager would.
 *
 * The actions move between the fixture's examples the way the engine would:
 * turning routing on from `idle` routes; off from any welcome state is idle;
 * pausing AdGuard lets a waiting engine route (the `filtering` example has
 * AdGuard's service stopped); starting it again makes the engine wait.
 * Nothing else is invented.
 */
import fixture from "./fixtures/engine-probe-v2.json";
import type { EngineSource } from "./engine-source";
import { parseEngineProbe, parseEngineStatus, type EnginePolicy, type EngineStatus } from "./protocol";

export const ENGINE_SCENARIOS = [
  "missing",
  "stopped",
  "starting",
  "idle",
  "filtering",
  "adguard",
  "vpn",
  "crash_loop",
  "setup",
  "incompatible",
  "refused",
  "unreachable",
  "error",
] as const;
export type EngineScenario = (typeof ENGINE_SCENARIOS)[number];

export const MOCK_ENGINE_ERROR = "service manager: Access is denied. (os error 5)";
/** What the mock's AdGuard actions answer when they cannot apply (no AdGuard to stop or start). */
export const MOCK_ADGUARD_ERROR = "Adguard Service: the service is not in a state that allows this";

const WELCOME: readonly EngineScenario[] = ["idle", "filtering", "adguard", "vpn", "crash_loop", "setup"];

function statusOf(scenario: EngineScenario): EngineStatus {
  const example = fixture.examples[scenario as keyof typeof fixture.examples];
  return parseEngineStatus((example.pipe as { status: unknown }).status);
}

export function createMockEngine(start: EngineScenario = "missing"): EngineSource {
  let scenario = start;
  const requireWelcome = () => {
    if (!WELCOME.includes(scenario)) throw new Error("The system cannot find the file specified. (os error 2)");
  };
  return {
    kind: "mock",
    probe: async () => {
      if (scenario === "error") throw new Error(MOCK_ENGINE_ERROR);
      return parseEngineProbe(fixture.examples[scenario]);
    },
    setPolicy: async (policy: EnginePolicy) => {
      requireWelcome();
      if (!policy.engine) scenario = "idle";
      else if (scenario === "idle" || scenario === "crash_loop") scenario = "filtering";
      return statusOf(scenario);
    },
    stopAdguard: async () => {
      if (scenario !== "adguard") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "filtering";
    },
    startAdguard: async () => {
      if (scenario !== "filtering") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard";
    },
  };
}
