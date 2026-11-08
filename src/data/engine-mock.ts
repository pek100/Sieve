/**
 * Mock engine: answers `probe` with one of the examples of the wire fixture
 * (src/data/fixtures/engine-probe-v3.json), so the browser, tests and e2e
 * show exactly the shapes Rust produces. Query string `?engine=<scenario>`,
 * default `missing` (a browser has no engine). `error` makes every probe
 * fail, as an unreadable service manager would.
 *
 * The actions move between the fixture's examples the way the engine would:
 * turning routing on from `idle` routes; off from any welcome state is idle;
 * pausing AdGuard lets a waiting engine route with AdGuard's service left
 * stopping (`adguard_paused`, as the real AdGuard does); starting a service
 * that is really stopped (the `filtering` example) makes the engine wait, and
 * a stopping one cannot be started; requesting an update while one is on offer
 * starts applying it, and any other request answers the state as it is. The rest of a sent policy is held and
 * echoed, as the engine would, so the controller sees it in force. Nothing
 * else is invented.
 *
 * `logTail` answers only in scenarios where the engine routes (`filtering`,
 * `hosts`), as a real engine would: every row of the log fixture on the first
 * read, then its host-level rows cycled, one per read, content from the seed
 * and the read count. Hosts are under `example.*`, addresses from the
 * documentation ranges. `?log=error` makes every read fail.
 *
 * The certificate answers `certStatuses` of the IPC fixture, chosen by
 * `?cert=<scenario>` (default `not_installed`); `error` makes each read fail.
 * Turning `https` off leaves `policy_off`, and on or Reinstall leaves
 * `installed`, as the engine does; Reinstall is refused while `https` is off.
 *
 * What is not decrypted answers the `exclusions` example of the IPC fixture;
 * "Try decrypting again" takes an `auto:*` row away, as the engine would.
 * `?heal=1` is an engine that holds `https` on: the app cannot turn it on while
 * `filtering.https` is unavailable, so this mock refuses being told off (refused
 * policies are retried at the next probe, not at once), and it has nothing to
 * tell on the first read, then one exclusion, then a second of the same group.
 */
import { hash01 } from "./prng";
import fixture from "./fixtures/engine-probe-v3.json";
import ipc from "./fixtures/engine-ipc-v3.json";
import logFixture from "./fixtures/engine-log-v1.json";
import type { EngineSource } from "./engine-source";
import {
  LOG_TAIL_VERSION,
  parseCertStatus,
  parseDnsUpstreams,
  parseEngineLists,
  parseEngineProbe,
  parseEngineStatus,
  parseExclusionsPage,
  parseHealNotices,
  parseLogTail,
  type CertStatus,
  type EngineLists,
  type EnginePolicy,
  type EngineStatus,
  type LogEntry,
} from "./protocol";

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
  "update_current",
  "update_available",
  "update_applying",
  "update_stale",
  "update_failed",
  "update_refused",
  "update_rolled_back",
] as const;
export type EngineScenario = (typeof ENGINE_SCENARIOS)[number];

export const CERT_SCENARIOS = ["installed", "expires_soon", "not_installed", "policy_off", "removal_pending", "error"] as const;
export type CertScenario = (typeof CERT_SCENARIOS)[number];

export const MOCK_ENGINE_ERROR = "service manager: Access is denied. (os error 5)";
/** What the mock's AdGuard actions answer when they cannot apply (no AdGuard to stop or start). */
export const MOCK_ADGUARD_ERROR = "Adguard Service: the service is not in a state that allows this";
/** The engine's refusals of a certificate request (`?cert=error`, Reinstall with `https` off). */
export const MOCK_CERT_ERROR = "unexpected answer: the engine did not say";
export const MOCK_HTTPS_OFF = "HTTPS filtering is off, so there is no certificate to reinstall";

/** A mock engine that holds `https` on says this when told off (`?heal=1`). */
export const MOCK_HOLDS_HTTPS = "this mock engine holds HTTPS on";

/** The message of a failed log read (?log=error). */
export const MOCK_LOG_ERROR = "the engine's log could not be read";

const WELCOME: readonly EngineScenario[] = [
  "idle",
  "filtering",
  "hosts",
  "adguard",
  "adguard_paused",
  "vpn",
  "crash_loop",
  "setup",
  "update_current",
  "update_available",
  "update_applying",
  "update_stale",
  "update_failed",
  "update_refused",
  "update_rolled_back",
];
const ROUTES: readonly EngineScenario[] = ["filtering", "hosts", "adguard_paused"];

function statusOf(scenario: EngineScenario): EngineStatus {
  const example = fixture.examples[scenario as keyof typeof fixture.examples];
  return parseEngineStatus((example.pipe as { status: unknown }).status);
}

export function createMockEngine(start: EngineScenario = "missing", options: { seed?: number; logError?: boolean; cert?: CertScenario; heal?: boolean; run?: number } = {}): EngineSource {
  let scenario = start;
  let held: Omit<EnginePolicy, "revision" | "engine"> | null = null;
  const holdsHttps = options.heal === true;
  const echo = (status: EngineStatus): EngineStatus => {
    const policy = held ? { ...status.policy, ...held } : status.policy;
    if (!holdsHttps) return { ...status, policy };
    // As the engine: its switch alone decrypts nothing, with routes down or sieving off.
    return { ...status, decrypting: status.routes_up && policy.sieving, policy: { ...policy, https: true } };
  };
  const seed = options.seed ?? 1;
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
  let upstreams = parseDnsUpstreams(ipc.engine.find((m) => m.type === "dns_upstreams"));
  let cert = options.cert ?? "not_installed";
  let https = false;
  /**
   * AdGuard's service as it stands once the engine went idle: the idle example
   * has no AdGuard, but turning routing off does not uninstall it.
   */
  let adguardWhileIdle: "running" | "stopped" | null = null;
  const requireWelcome = () => {
    if (!WELCOME.includes(scenario)) throw new Error("The system cannot find the file specified. (os error 2)");
  };
  const lists = async (): Promise<EngineLists> => {
    requireWelcome();
    return parseEngineLists(ipc.engine.find((m) => m.type === "lists"));
  };
  const certAnswer = (): CertStatus => {
    if (cert === "error") throw new Error(MOCK_CERT_ERROR);
    return parseCertStatus(ipc.certStatuses[cert]);
  };
  const excluded = parseExclusionsPage(ipc.engine.find((m) => m.type === "exclusions"));
  let rows = excluded.rows;
  let rowsRevision = excluded.revision;
  const page = (after: number) => ({ ...excluded, revision: rowsRevision, rows: rows.slice(after), total: rows.length });
  let healReads = 0;
  const first = parseHealNotices(ipc.engine.find((m) => m.type === "heal_notices")).notices[0];
  return {
    kind: "mock",
    probe: async () => {
      if (scenario === "error") throw new Error(MOCK_ENGINE_ERROR);
      const probe = parseEngineProbe(fixture.examples[scenario]);
      const withHeld = probe.pipe?.kind === "welcome" ? { ...probe, pipe: { ...probe.pipe, status: echo(probe.pipe.status) } } : probe;
      return adguardWhileIdle === null ? withHeld : { ...withHeld, adguard: adguardWhileIdle };
    },
    setPolicy: async (policy: EnginePolicy) => {
      requireWelcome();
      if (holdsHttps && !policy.https) throw new Error(MOCK_HOLDS_HTTPS);
      if (!policy.engine) {
        if (scenario === "adguard") adguardWhileIdle = "running";
        if (scenario === "filtering" && adguardWhileIdle === null) adguardWhileIdle = "stopped";
        scenario = "idle";
        // The update examples are the idle engine with another update state.
      } else if (scenario === "idle" || scenario === "crash_loop" || scenario.startsWith("update_")) {
        // A running AdGuard keeps the engine waiting; otherwise it routes.
        scenario = adguardWhileIdle === "running" ? "adguard" : "filtering";
        adguardWhileIdle = null;
      }
      if (https && !policy.https) cert = "policy_off";
      if (!https && policy.https && (cert === "policy_off" || cert === "not_installed")) cert = "installed";
      https = policy.https;
      held = { sieving: policy.sieving, off_apps: policy.off_apps, lists: policy.lists, domain_lists: policy.domain_lists, https: policy.https, content: policy.content, plain_dns: policy.plain_dns, user_rules: policy.user_rules, exclusions: policy.exclusions };
      return echo(statusOf(scenario));
    },
    dnsUpstreams: async () => {
      requireWelcome();
      return upstreams;
    },
    setDnsUpstreams: async (list) => {
      requireWelcome();
      if (list.revision <= upstreams.revision) throw new Error(`stale list revision ${list.revision} (the engine holds ${upstreams.revision})`);
      upstreams = list;
      return upstreams;
    },
    requestUpdate: async () => {
      requireWelcome();
      if (scenario === "update_available") scenario = "update_applying";
      return echo(statusOf(scenario));
    },
    lists,
    listsRefresh: lists,
    stopAdguard: async () => {
      if (adguardWhileIdle === "running") {
        adguardWhileIdle = "stopped";
        return;
      }
      if (scenario !== "adguard") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard_paused";
    },
    startAdguard: async () => {
      if (adguardWhileIdle === "stopped") {
        adguardWhileIdle = "running";
        return;
      }
      if (scenario !== "filtering" && scenario !== "hosts") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard";
    },
    logTail: async (since) => {
      if (options.logError) throw new Error(MOCK_LOG_ERROR);
      const rows = ROUTES.includes(scenario) ? nextRows().filter((e) => e.seq > since) : [];
      return { v: LOG_TAIL_VERSION, next: rows.at(-1)?.seq ?? since, dropped: 0, rows, skipped: 0 };
    },
    certStatus: async () => {
      requireWelcome();
      return certAnswer();
    },
    installRoot: async () => {
      requireWelcome();
      if (!https) throw new Error(MOCK_HTTPS_OFF);
      cert = "installed";
      return certAnswer();
    },
    exclusions: async (after) => {
      requireWelcome();
      return page(after);
    },
    tryDecryptAgain: async (line, app, reason) => {
      requireWelcome();
      if (line === null && app === null) throw new Error("try again needs a line or an app");
      const named = (r: (typeof rows)[number]) => r.reason.startsWith("auto:") && (line === null ? r.reason === "auto:pinning" && r.apps.includes(app ?? "") : r.line === line && (r.apps[0] ?? null) === app && r.reason === reason);
      if (rows.some(named)) {
        rows = rows.filter((r) => !named(r));
        rowsRevision += 1;
      }
      return page(0);
    },
    healNotices: async (after) => {
      requireWelcome();
      const run = options.run ?? 1;
      if (!holdsHttps) return { run, revision: 0, exclusions_revision: rowsRevision, notices: [] };
      healReads += 1;
      const rev = Math.min(healReads - 1, first.hosts.length);
      const notice = { ...first, hosts: first.hosts.slice(0, rev), total: rev, rev };
      return { run, revision: rev, exclusions_revision: rowsRevision, notices: rev > after ? [notice] : [] };
    },
  };
}
