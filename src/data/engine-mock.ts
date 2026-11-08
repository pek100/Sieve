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
 *
 * Apps' problems answer per `?issues=` (see ISSUES_SCENARIOS), moved to the clock.
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
  parseIssues,
  parseLogTail,
  type CertStatus,
  type EngineCustomList,
  type EngineListStatus,
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

/** What the mock's own lists hold, when they were downloaded, and its rules view (as the engine caps it). */
export const MOCK_OWN_RULES = 1_204;
export const MOCK_FETCHED_AT_MS = Date.UTC(2026, 10, 8, 9, 30);
const MOCK_RULES_TOTAL = 420;
const MOCK_RULES_SHOWN = 200;

export const IMPORT_ANSWERS = ["ok", "cancel", "refused"] as const;

/**
 * `?issues=`: `some` answers the IPC fixture's example while the engine routes,
 * `partial` an answer with missing, unknown and broken fields (degraded data),
 * `error` fails every read; `none`, the default, has no app in trouble.
 */
export const ISSUES_SCENARIOS = ["none", "some", "partial", "error"] as const;
export type IssuesScenario = (typeof ISSUES_SCENARIOS)[number];
export const MOCK_ISSUES_ERROR = "the engine's problems could not be read";

const issuesExample = parseIssues(ipc.engine.find((m) => m.type === "issues"));
const ISSUES_EXAMPLE_NEWEST = Math.max(...issuesExample.apps.flatMap((a) => a.problems.map((p) => p.last_ms)));

/** Old-schema and broken data the parser must survive: no counts, an unknown signal, a nameless app. */
const PARTIAL_ISSUES = {
  run: 1,
  revision: 3,
  apps: [
    { key: "game launcher", problems: [{ signal: "app_refused_certificate", cause: "sieve", host: "cdn.game.example", count: 2, last_ms: ISSUES_EXAMPLE_NEWEST }, { signal: "teleported", cause: "sieve", count: 1, last_ms: 1 }] },
    { key: "", problems: [{ signal: "stall", cause: "unknown", count: 1, last_ms: 1 }] },
    { key: "updater", exe: 7, problems: [{ signal: "blocked", cause: "sieve", count: 3, last_ms: ISSUES_EXAMPLE_NEWEST - 30_000 }] },
    null,
  ],
};

export function createMockEngine(
  start: EngineScenario = "missing",
  options: { seed?: number; logError?: boolean; cert?: CertScenario; heal?: boolean; run?: number; importAnswer?: (typeof IMPORT_ANSWERS)[number]; issues?: IssuesScenario; now?: () => number } = {},
): EngineSource {
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
  // Own lists the engine was told of, and the one it was asked to download now.
  const ownRow = (c: EngineCustomList): EngineListStatus => {
    const refused = c.url !== null && /html|broken/i.test(c.url);
    return {
      id: c.id,
      enabled: c.enabled,
      fetched_at_ms: refused ? null : MOCK_FETCHED_AT_MS,
      refresh_s: refused ? null : 86_400,
      last_error: refused ? "an HTML page, not a filter list" : null,
      network: refused || !c.enabled ? 0 : MOCK_OWN_RULES,
      cosmetic: 0,
      skipped: 0,
      skip_reasons: {},
      skipped_exceptions: [],
      skipped_exceptions_total: 0,
    };
  };
  const lists = async (): Promise<EngineLists> => {
    requireWelcome();
    const report = parseEngineLists(ipc.engine.find((m) => m.type === "lists"));
    return { ...report, lists: [...report.lists, ...(held?.custom_lists ?? []).map(ownRow)] };
  };
  // A catalogue id, or one of the own lists it holds.
  const knownList = (id: string) => !id.startsWith("custom-") || (held?.custom_lists ?? []).some((c) => c.id === id);
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
      held = { sieving: policy.sieving, off_apps: policy.off_apps, lists: policy.lists, domain_lists: policy.domain_lists, https: policy.https, content: policy.content, plain_dns: policy.plain_dns, user_rules: policy.user_rules, exclusions: policy.exclusions, custom_lists: policy.custom_lists ?? [], tracking: policy.https ? (policy.tracking ?? []) : [] };
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
    listRefresh: async (id) => {
      requireWelcome();
      if (!knownList(id)) throw new Error("the engine knows no list by that id");
      return lists();
    },
    listRules: async (id, query) => {
      requireWelcome();
      // A copy of the rules a list of this id would hold, the same on every read.
      const all = Array.from({ length: MOCK_RULES_TOTAL }, (_, i) => `||${["ads", "track", "pixel", "banner"][i % 4]}${i}.${id}.example^`);
      const found = all.filter((r) => r.toLowerCase().includes(query.trim().toLowerCase()));
      return { id, lines: found.slice(0, MOCK_RULES_SHOWN), matched: found.length, total: all.length };
    },
    listImport: async () => {
      requireWelcome();
      if (options.importAnswer === "cancel") return null;
      if (options.importAnswer === "refused") throw new Error("an HTML page, not a filter list");
      return { name: "My blocklist", rules: MOCK_OWN_RULES, skipped: 0 };
    },
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
    issues: async (after) => {
      requireWelcome();
      const run = options.run ?? 1;
      const kind = options.issues ?? "none";
      if (kind === "error") throw new Error(MOCK_ISSUES_ERROR);
      if (kind === "none" || !ROUTES.includes(scenario)) return { run, revision: 0, apps: [], dropped: 0 };
      const answer = kind === "partial" ? parseIssues(PARTIAL_ISSUES) : issuesExample;
      // The example's times moved so its newest problem was a minute ago.
      const shift = (options.now ?? Date.now)() - ISSUES_EXAMPLE_NEWEST - 60_000;
      const apps = answer.apps.map((a) => ({ ...a, since_ms: a.since_ms + shift, problems: a.problems.map((p) => ({ ...p, first_ms: p.first_ms + shift, last_ms: p.last_ms + shift })) }));
      return { ...answer, run, apps: answer.revision > after || after === 0 ? apps : [] };
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
