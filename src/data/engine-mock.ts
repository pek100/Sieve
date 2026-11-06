/**
 * Mock engine: answers `probe` with one of the examples of the wire fixture
 * (src/data/fixtures/engine-probe-v2.json), so the browser, tests and e2e
 * show exactly the shapes Rust produces. Query string `?engine=<scenario>`,
 * default `missing` (a browser has no engine). `error` makes every probe
 * fail, as an unreadable service manager would.
 *
 * The actions move between the fixture's examples the way the engine would:
 * turning routing on from `idle` routes; off from any welcome state is idle;
 * pausing AdGuard lets a waiting engine route with AdGuard's service left
 * stopping (`adguard_paused`, as the real AdGuard does); starting a service
 * that is really stopped (the `filtering` example) makes the engine wait, and
 * a stopping one cannot be started. The rest of a sent policy is held and
 * echoed, as the engine would, so the controller sees it in force. Nothing
 * else is invented.
 *
 * `logTail` answers only in scenarios where the engine routes (`filtering`,
 * `hosts`), as a real engine would: every row of the log fixture on the first
 * read, then its host-level rows cycled, one per read, content from the seed
 * and the read count. Hosts are under `example.*`, addresses from the
 * documentation ranges. `?log=error` makes every read fail.
 */
import { hash01 } from "./prng";
import fixture from "./fixtures/engine-probe-v2.json";
import ipc from "./fixtures/engine-ipc-v3.json";
import logFixture from "./fixtures/engine-log-v1.json";
import type { EngineSource } from "./engine-source";
import { LOG_TAIL_VERSION, parseEngineLists, parseEngineProbe, parseEngineStatus, parseLogTail, type EngineLists, type EnginePolicy, type EngineStatus, type LogEntry } from "./protocol";

export const ENGINE_SCENARIOS = [
  "missing",
  "stopped",
  "starting",
  "idle",
  "filtering",
  "hosts",
  "adguard",
  "adguard_paused",
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

/** The message of a failed log read (?log=error). */
export const MOCK_LOG_ERROR = "the engine's log could not be read";

const WELCOME: readonly EngineScenario[] = ["idle", "filtering", "hosts", "adguard", "adguard_paused", "vpn", "crash_loop", "setup"];
const ROUTES: readonly EngineScenario[] = ["filtering", "hosts", "adguard_paused"];

function statusOf(scenario: EngineScenario): EngineStatus {
  const example = fixture.examples[scenario as keyof typeof fixture.examples];
  return parseEngineStatus((example.pipe as { status: unknown }).status);
}

export function createMockEngine(start: EngineScenario = "missing", log: { seed?: number; logError?: boolean } = {}): EngineSource {
  let scenario = start;
  let held: Omit<EnginePolicy, "revision" | "engine"> | null = null;
  const echo = (status: EngineStatus): EngineStatus => (held ? { ...status, policy: { ...status.policy, ...held } } : status);
  const seed = log.seed ?? 1;
  const all = parseLogTail(logFixture).rows;
  const hostLevel = all.filter((e) => e.row.url === null);
  let reads = 0;
  let seq = 0;
  /** One read's rows: the whole fixture, then one cycled host-level row, a new seq and time each. */
  const nextRows = (): LogEntry[] => {
    reads += 1;
    const from = reads === 1 ? all : [hostLevel[Math.floor(hash01(seed, reads) * hostLevel.length)]];
    return from.map((e) => {
      seq += 1;
      return { seq, row: { ...e.row, id: seq, t: e.row.t + (reads - 1) * 1000 } };
    });
  };
  const requireWelcome = () => {
    if (!WELCOME.includes(scenario)) throw new Error("The system cannot find the file specified. (os error 2)");
  };
  const lists = async (): Promise<EngineLists> => {
    requireWelcome();
    return parseEngineLists(ipc.engine.find((m) => m.type === "lists"));
  };
  return {
    kind: "mock",
    probe: async () => {
      if (scenario === "error") throw new Error(MOCK_ENGINE_ERROR);
      const probe = parseEngineProbe(fixture.examples[scenario]);
      return probe.pipe?.kind === "welcome" ? { ...probe, pipe: { ...probe.pipe, status: echo(probe.pipe.status) } } : probe;
    },
    setPolicy: async (policy: EnginePolicy) => {
      requireWelcome();
      if (!policy.engine) scenario = "idle";
      else if (scenario === "idle" || scenario === "crash_loop") scenario = "filtering";
      held = { sieving: policy.sieving, off_apps: policy.off_apps, lists: policy.lists, domain_lists: policy.domain_lists };
      return echo(statusOf(scenario));
    },
    lists,
    listsRefresh: lists,
    stopAdguard: async () => {
      if (scenario !== "adguard") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard_paused";
    },
    startAdguard: async () => {
      if (scenario !== "filtering" && scenario !== "hosts") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard";
    },
    logTail: async (since) => {
      if (log.logError) throw new Error(MOCK_LOG_ERROR);
      const rows = ROUTES.includes(scenario) ? nextRows().filter((e) => e.seq > since) : [];
      return { v: LOG_TAIL_VERSION, next: rows.at(-1)?.seq ?? since, dropped: 0, rows, skipped: 0 };
    },
  };
}
