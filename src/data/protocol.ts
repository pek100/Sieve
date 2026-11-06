/**
 * Snapshot protocol v1 (primitive B1). Mirrored in src-tauri/src/protocol.rs.
 * Raw facts about the machine only, no judgement: which processes exist and
 * which sockets they own. Changing the shape bumps PROTOCOL_VERSION and the
 * fixture (src/data/fixtures/snapshot-v1.json) in the same commit.
 */
import { GRAIN_NAMES, type GrainName } from "@/core/history";

export const PROTOCOL_VERSION = 1 as const;

export const PROTOS = ["tcp", "udp"] as const;
export type Proto = (typeof PROTOS)[number];

export const FAMILIES = ["v4", "v6"] as const;
export type Family = (typeof FAMILIES)[number];

/** TCP states in MIB_TCP_STATE order (code 1 to 12), then `none` for UDP. */
export const FLOW_STATES = [
  "closed",
  "listen",
  "syn_sent",
  "syn_received",
  "established",
  "fin_wait_1",
  "fin_wait_2",
  "close_wait",
  "closing",
  "last_ack",
  "time_wait",
  "delete_tcb",
  "none",
] as const;
export type FlowState = (typeof FLOW_STATES)[number];

export interface Endpoint {
  addr: string;
  port: number;
}

export interface ProcessInfo {
  pid: number;
  /** Full image path, or null when the OS refused to tell us. */
  exe: string | null;
  /** Display name: exe file name, or "System" / "pid <n>" when exe is null. */
  name: string;
  /** ProductName from the exe's version info, when present. */
  product: string | null;
}

export interface Flow {
  pid: number;
  proto: Proto;
  family: Family;
  local: Endpoint;
  /** null for listening TCP sockets and for every UDP socket. */
  remote: Endpoint | null;
  state: FlowState;
}

export interface Snapshot {
  v: typeof PROTOCOL_VERSION;
  /** Sample time, ms since the Unix epoch, from the sampling side's clock. */
  t: number;
  processes: ProcessInfo[];
  flows: Flow[];
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(`Snapshot protocol: ${message}`);
    this.name = "ProtocolError";
  }
}

type Rec = Record<string, unknown>;

function isRec(x: unknown): x is Rec {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function int(x: unknown, where: string): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < 0) {
    throw new ProtocolError(`${where} must be a non-negative integer`);
  }
  return x;
}

function str(x: unknown, where: string): string {
  if (typeof x !== "string") throw new ProtocolError(`${where} must be a string`);
  return x;
}

function strOrNull(x: unknown, where: string): string | null {
  return x === null ? null : str(x, where);
}

function oneOf<T extends string>(x: unknown, options: readonly T[], where: string): T {
  if (typeof x !== "string" || !(options as readonly string[]).includes(x)) {
    throw new ProtocolError(`${where} must be one of ${options.join(", ")}`);
  }
  return x as T;
}

function endpoint(x: unknown, where: string): Endpoint {
  if (!isRec(x)) throw new ProtocolError(`${where} must be an object`);
  const port = int(x.port, `${where}.port`);
  if (port > 65535) throw new ProtocolError(`${where}.port out of range`);
  return { addr: str(x.addr, `${where}.addr`), port };
}

// ---------------------------------------------------------------------------
// Persisted history (plan row 77). Mirror of History in protocol.rs; fixture
// src/data/fixtures/history-v1.json. Grain names and retention live in
// src/core/history.ts (GRAINS).

/** One sample folded into history: what the Tauri source sends after each sample. */
export interface HistoryRecord {
  t: number;
  apps: { app: string; name: string; flows: number }[];
}

/** How many samples a bucket holds. A bucket with no samples is absent: no data, not zero. */
export interface SampleBucket {
  t: number;
  n: number;
}

/** Active flows of one app summed over a bucket's samples. Absent in a sampled bucket means 0. */
export interface AppBucket {
  t: number;
  app: string;
  name: string;
  flows: number;
}

export interface History {
  v: typeof PROTOCOL_VERSION;
  grain: GrainName;
  step: number;
  /** Oldest first. */
  samples: SampleBucket[];
  /** Oldest first, then by app key. */
  apps: AppBucket[];
}

/** Validate an untrusted value as v1 History. Throws ProtocolError. */
export function parseHistory(x: unknown): History {
  if (!isRec(x)) throw new ProtocolError("history must be an object");
  if (x.v !== PROTOCOL_VERSION) throw new ProtocolError(`history version ${String(x.v)} is not ${PROTOCOL_VERSION}`);
  const grain = oneOf(x.grain, GRAIN_NAMES, "grain");
  const step = int(x.step, "step");
  if (!Array.isArray(x.samples)) throw new ProtocolError("samples must be an array");
  if (!Array.isArray(x.apps)) throw new ProtocolError("apps must be an array");
  const samples = x.samples.map((s, i): SampleBucket => {
    if (!isRec(s)) throw new ProtocolError(`samples[${i}] must be an object`);
    return { t: int(s.t, `samples[${i}].t`), n: int(s.n, `samples[${i}].n`) };
  });
  const apps = x.apps.map((a, i): AppBucket => {
    const w = `apps[${i}]`;
    if (!isRec(a)) throw new ProtocolError(`${w} must be an object`);
    return { t: int(a.t, `${w}.t`), app: str(a.app, `${w}.app`), name: str(a.name, `${w}.name`), flows: int(a.flows, `${w}.flows`) };
  });
  return { v: PROTOCOL_VERSION, grain, step, samples, apps };
}

// ---------------------------------------------------------------------------
// DNS filter (phase B). Mirrors of src-tauri/src/dns/status.rs (dns_status),
// src-tauri/src/dns/probe.rs (dns_self_check) and src-tauri/src/windns.rs
// (windows_dns, read only). Wire names are Rust's snake_case. Fixtures:
// src/data/fixtures/dns-status-v3.json, windows-dns-v1.json (Rust reads them too).

export const DNS_STATUS_VERSION = 3 as const;
export const WINDOWS_DNS_VERSION = 1 as const;

export interface DnsCounters {
  /** Every query received. */
  queries: number;
  /** Answered by Sieve with the block answer. */
  blocked: number;
  /** Answered by an upstream. */
  forwarded: number;
  /** Every upstream failed: SERVFAIL sent. */
  failed: number;
  /** Blocked but past the per-name tracking cap. */
  untracked: number;
}

export interface DnsListInfo {
  url: string | null;
  /** When the list in use was downloaded, ms since the epoch; null: no list. */
  fetched_at: number | null;
  rules: number;
  allow: number;
  skipped: number;
  user_rules: boolean;
  /** Why the list is stale or missing, or null. */
  error: string | null;
}

export interface DomainCount {
  domain: string;
  count: number;
}

export interface DnsStatus {
  v: typeof DNS_STATUS_VERSION;
  running: boolean;
  /** Running but forwarding everything, blocking nothing (the global Sieving switch is off). */
  pass_through: boolean;
  /** Every address the proxy listens on; empty when stopped. */
  binds: string[];
  started_at: number | null;
  upstreams: string[];
  counters: DnsCounters;
  last_error: string | null;
  list: DnsListInfo;
  /** At most 20, most blocked first. */
  top_blocked: DomainCount[];
}

/**
 * What a check tests, as Rust's `CheckKind` (probe.rs) names it:
 * `rules` at least one block rule is loaded (no server), `canary` the
 * built-in test name gets the block answer, `resolve` a normal name
 * resolves through the upstreams.
 */
export const CHECK_KINDS = ["rules", "canary", "resolve"] as const;
/** `call` is never on the wire: the window's own record that the dns_self_check command itself failed. */
export type DnsCheckKind = (typeof CHECK_KINDS)[number] | "call";

export interface DnsCheck {
  kind: DnsCheckKind;
  /** The listen address that was asked; empty for a check no listener answers (`rules`, `call`). */
  server: string;
  name: string;
  expect: string;
  got: string;
  pass: boolean;
}

export interface SelfCheck {
  pass: boolean;
  checks: DnsCheck[];
}

/** One active adapter's DNS servers in force (Rust `windns::AdapterDns`). */
export interface AdapterDns {
  /** The adapter's name as Windows' network settings show it. */
  alias: string;
  index: number;
  /** IPv4 and IPv6 servers in Windows' order, as address text ("127.0.0.1", "::1"). */
  servers: string[];
}

/** `windows_dns`: read only, what Windows asks for DNS. Sieve never changes it. */
export interface WindowsDns {
  v: typeof WINDOWS_DNS_VERSION;
  /** Active adapters: up, not loopback, not a tunnel. */
  adapters: AdapterDns[];
}

function bool(x: unknown, where: string): boolean {
  if (typeof x !== "boolean") throw new ProtocolError(`${where} must be a boolean`);
  return x;
}

function intOrNull(x: unknown, where: string): number | null {
  return x === null ? null : int(x, where);
}

function strings(x: unknown, where: string): string[] {
  if (!Array.isArray(x)) throw new ProtocolError(`${where} must be an array`);
  return x.map((s, i) => str(s, `${where}[${i}]`));
}

function rec(x: unknown, where: string): Rec {
  if (!isRec(x)) throw new ProtocolError(`${where} must be an object`);
  return x;
}

function version(x: Rec, want: number, what: string): void {
  if (x.v !== want) {
    throw new ProtocolError(
      `${what} version ${String(x.v)} is not ${want}: the Sieve backend and this window disagree. Restart Sieve after updating.`,
    );
  }
}

/** Validate an untrusted `dns_status` answer. Throws ProtocolError. */
export function parseDnsStatus(raw: unknown): DnsStatus {
  const x = rec(raw, "dns status");
  version(x, DNS_STATUS_VERSION, "dns status");
  const c = rec(x.counters, "counters");
  const l = rec(x.list, "list");
  if (!Array.isArray(x.top_blocked)) throw new ProtocolError("top_blocked must be an array");
  return {
    v: DNS_STATUS_VERSION,
    running: bool(x.running, "running"),
    pass_through: bool(x.pass_through, "pass_through"),
    binds: strings(x.binds, "binds"),
    started_at: intOrNull(x.started_at, "started_at"),
    upstreams: strings(x.upstreams, "upstreams"),
    counters: {
      queries: int(c.queries, "counters.queries"),
      blocked: int(c.blocked, "counters.blocked"),
      forwarded: int(c.forwarded, "counters.forwarded"),
      failed: int(c.failed, "counters.failed"),
      untracked: int(c.untracked, "counters.untracked"),
    },
    last_error: strOrNull(x.last_error, "last_error"),
    list: {
      url: strOrNull(l.url, "list.url"),
      fetched_at: intOrNull(l.fetched_at, "list.fetched_at"),
      rules: int(l.rules, "list.rules"),
      allow: int(l.allow, "list.allow"),
      skipped: int(l.skipped, "list.skipped"),
      user_rules: bool(l.user_rules, "list.user_rules"),
      error: strOrNull(l.error, "list.error"),
    },
    top_blocked: x.top_blocked.map((d, i) => {
      const r = rec(d, `top_blocked[${i}]`);
      return { domain: str(r.domain, `top_blocked[${i}].domain`), count: int(r.count, `top_blocked[${i}].count`) };
    }),
  };
}

/** Validate an untrusted `dns_self_check` answer. Throws ProtocolError. */
export function parseSelfCheck(raw: unknown): SelfCheck {
  const x = rec(raw, "self check");
  if (!Array.isArray(x.checks)) throw new ProtocolError("checks must be an array");
  return {
    pass: bool(x.pass, "pass"),
    checks: x.checks.map((c, i) => {
      const r = rec(c, `checks[${i}]`);
      const w = `checks[${i}]`;
      const kind = CHECK_KINDS.find((k) => k === r.kind);
      if (kind === undefined) throw new ProtocolError(`${w}.kind must be one of ${CHECK_KINDS.join(", ")}`);
      return {
        kind,
        server: str(r.server, `${w}.server`),
        name: str(r.name, `${w}.name`),
        expect: str(r.expect, `${w}.expect`),
        got: str(r.got, `${w}.got`),
        pass: bool(r.pass, `${w}.pass`),
      };
    }),
  };
}

/** Validate an untrusted `windows_dns` answer. Throws ProtocolError. */
export function parseWindowsDns(raw: unknown): WindowsDns {
  const x = rec(raw, "windows dns");
  version(x, WINDOWS_DNS_VERSION, "windows dns");
  if (!Array.isArray(x.adapters)) throw new ProtocolError("adapters must be an array");
  return {
    v: WINDOWS_DNS_VERSION,
    adapters: x.adapters.map((it, i) => {
      const w = `adapters[${i}]`;
      const r = rec(it, w);
      return { alias: str(r.alias, `${w}.alias`), index: int(r.index, `${w}.index`), servers: strings(r.servers, `${w}.servers`) };
    }),
  };
}

/**
 * `engine_probe` (Rust `engine::EngineProbe`, fixture
 * `src/data/fixtures/engine-probe-v2.json`): the filtering engine from
 * facts. `service` is the Windows service's state ("missing" when not
 * installed); `pipe` is the engine's own answer, asked only while the service
 * runs. `status` is the engine's `sieve-ipc` Status (protocol 3, fixture
 * `engine-ipc-v3.json`). The status carries the policy, the blocker, the
 * split tunnels and the engine's counters; the probe also reads AdGuard's
 * service state (`adguard`), for the pause offer. Fields protocol 3 added read
 * as their typed defaults when absent, so an older answer degrades, not throws.
 */
export const ENGINE_PROBE_VERSION = 2 as const;
export const SERVICE_FACTS = ["missing", "stopped", "starting", "stopping", "running", "other"] as const;
export type ServiceFact = (typeof SERVICE_FACTS)[number];
export const PIPE_KINDS = ["welcome", "incompatible", "refused", "unreachable"] as const;
/** `sieve-ipc` Blocker kinds, in declaration order. */
export const BLOCKER_KINDS = ["adguard", "vpn", "crash_loop", "setup"] as const;

export type EngineBlocker =
  | { kind: "adguard"; service: string }
  | { kind: "vpn"; adapter: string }
  | { kind: "crash_loop"; starts: number }
  | { kind: "setup"; message: string };

export type DomainListKind = "block" | "allow";

export interface EngineDomainList {
  kind: DomainListKind;
  entries: string[];
  enabled: boolean;
}

export interface EnginePolicy {
  revision: number;
  engine: boolean;
  /** The global Sieve switch; off relays every flow. */
  sieving: boolean;
  /** App keys (`appIdentity`) and guest keys (`vm:<name>`) the user turned off. */
  off_apps: string[];
  /** Catalogue ids; null means the catalogue's defaults. */
  lists: string[] | null;
  domain_lists: EngineDomainList[];
}

export interface EngineCounters {
  flows: number;
  attributed: number;
  own_refused: number;
  dns_answers: number;
  packets_in: number;
  packets_out: number;
  not_unicast: number;
  blocked: number;
  forwarded: number;
  forwarded_named: number;
  etw_found: number;
  etw_disagreed: number;
  etw_dropped: number;
}

/** One row of "Virtual machines and WSL": what the engine has seen of one VM since it started. */
export interface EngineGuest {
  /** `sieve_ipc::vm_key`, its key in `apps.levels`. */
  key: string;
  /** Null is the unidentified row. */
  vm: string | null;
  seen: number;
  open: number;
}

export interface EngineStatus {
  filtering: boolean;
  routes_up: boolean;
  /** A compiled snapshot with at least one rule decides flows right now. */
  blocking: boolean;
  flows: number;
  decrypting: boolean;
  last_error: string | null;
  policy: EnginePolicy;
  blocker: EngineBlocker | null;
  split_tunnels: string[];
  counters: EngineCounters;
  guests: EngineGuest[];
}

const COUNTER_KEYS = [
  "flows",
  "attributed",
  "own_refused",
  "dns_answers",
  "packets_in",
  "packets_out",
  "not_unicast",
  "forwarded",
  "forwarded_named",
  "etw_found",
  "etw_disagreed",
  "etw_dropped",
] as const;

const GUEST_KEY_PREFIX = "vm:";

/** One guest row, or null when it is broken: the rest of the list still renders. */
function guest(raw: unknown): EngineGuest | null {
  if (raw === null || typeof raw !== "object") return null;
  const g = raw as Record<string, unknown>;
  const count = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (typeof g.key !== "string" || !g.key.startsWith(GUEST_KEY_PREFIX)) return null;
  if (g.vm !== null && typeof g.vm !== "string") return null;
  if (!count(g.seen) || !count(g.open)) return null;
  return { key: g.key, vm: g.vm, seen: g.seen as number, open: g.open as number };
}

/** The guests of a status. A missing or broken list is no guests: an optional group never fails the whole status. */
function guests(raw: unknown): EngineGuest[] {
  return Array.isArray(raw) ? raw.map(guest).filter((g) => g !== null) : [];
}

/** `raw` read by `parse`, or `fallback` when the field is absent (an older engine). */
function orDefault<T>(raw: unknown, parse: (v: unknown) => T, fallback: T): T {
  return raw === undefined ? fallback : parse(raw);
}

function domainLists(raw: unknown): EngineDomainList[] {
  if (!Array.isArray(raw)) throw new ProtocolError("policy.domain_lists must be an array");
  return raw.map((v, i) => {
    const d = rec(v, `domain_lists[${i}]`);
    return { kind: oneOf(d.kind, ["block", "allow"] as const, `domain_lists[${i}].kind`), entries: strings(d.entries, `domain_lists[${i}].entries`), enabled: bool(d.enabled, `domain_lists[${i}].enabled`) };
  });
}

function policy(raw: unknown): EnginePolicy {
  const p = rec(raw, "status.policy");
  return {
    revision: int(p.revision, "policy.revision"),
    engine: bool(p.engine, "policy.engine"),
    sieving: orDefault(p.sieving, (v) => bool(v, "policy.sieving"), false),
    off_apps: orDefault(p.off_apps, (v) => strings(v, "policy.off_apps"), []),
    lists: orDefault<string[] | null>(p.lists, (v) => (v === null ? null : strings(v, "policy.lists")), null),
    domain_lists: orDefault(p.domain_lists, domainLists, []),
  };
}

function blocker(raw: unknown): EngineBlocker {
  const b = rec(raw, "status.blocker");
  switch (b.kind) {
    case "adguard":
      return { kind: "adguard", service: str(b.service, "blocker.service") };
    case "vpn":
      return { kind: "vpn", adapter: str(b.adapter, "blocker.adapter") };
    case "crash_loop":
      return { kind: "crash_loop", starts: int(b.starts, "blocker.starts") };
    case "setup":
      return { kind: "setup", message: str(b.message, "blocker.message") };
    default:
      throw new ProtocolError(`blocker.kind must be one of ${BLOCKER_KINDS.join(", ")}`);
  }
}

/** Validate an untrusted engine Status (sieve-ipc). Throws ProtocolError. */
export function parseEngineStatus(raw: unknown): EngineStatus {
  const s = rec(raw, "status");
  const c = rec(s.counters, "status.counters");
  return {
    filtering: bool(s.filtering, "status.filtering"),
    routes_up: bool(s.routes_up, "status.routes_up"),
    blocking: orDefault(s.blocking, (v) => bool(v, "status.blocking"), false),
    flows: int(s.flows, "status.flows"),
    decrypting: bool(s.decrypting, "status.decrypting"),
    last_error: strOrNull(s.last_error, "status.last_error"),
    policy: policy(s.policy),
    blocker: s.blocker === null ? null : blocker(s.blocker),
    split_tunnels: strings(s.split_tunnels, "status.split_tunnels"),
    counters: {
      ...(Object.fromEntries(COUNTER_KEYS.map((k) => [k, int(c[k], `counters.${k}`)])) as Omit<EngineCounters, "blocked">),
      blocked: orDefault(c.blocked, (v) => int(v, "counters.blocked"), 0),
    },
    guests: guests(s.guests),
  };
}

/** One list in the engine's per-list report (sieve-ipc `ListStatus`). */
export interface EngineListStatus {
  id: string;
  enabled: boolean;
  fetched_at_ms: number | null;
  refresh_s: number | null;
  last_error: string | null;
  network: number;
  cosmetic: number;
  skipped: number;
  skip_reasons: Record<string, number>;
  /** The first 200 skipped exception lines, each cut short. */
  skipped_exceptions: string[];
  skipped_exceptions_total: number;
}

export interface EngineLists {
  lists: EngineListStatus[];
  compile_ms: number | null;
}

function absentOrInt(raw: unknown, what: string): number | null {
  return raw === null || raw === undefined ? null : int(raw, what);
}

function listStatus(raw: unknown, i: number): EngineListStatus {
  const w = `lists[${i}]`;
  const l = rec(raw, w);
  const reasons = l.skip_reasons === undefined ? {} : rec(l.skip_reasons, `.skip_reasons`);
  return {
    id: str(l.id, `.id`),
    enabled: bool(l.enabled, `.enabled`),
    fetched_at_ms: absentOrInt(l.fetched_at_ms, `.fetched_at_ms`),
    refresh_s: absentOrInt(l.refresh_s, `.refresh_s`),
    last_error: l.last_error === undefined ? null : strOrNull(l.last_error, `.last_error`),
    network: orDefault(l.network, (v) => int(v, `.network`), 0),
    cosmetic: orDefault(l.cosmetic, (v) => int(v, `.cosmetic`), 0),
    skipped: orDefault(l.skipped, (v) => int(v, `.skipped`), 0),
    skip_reasons: Object.fromEntries(Object.entries(reasons).map(([why, n]) => [why, int(n, `.skip_reasons`)])),
    skipped_exceptions: orDefault(l.skipped_exceptions, (v) => strings(v, `.skipped_exceptions`), []),
    skipped_exceptions_total: orDefault(l.skipped_exceptions_total, (v) => int(v, `.skipped_exceptions_total`), 0),
  };
}

/** Validate an untrusted `engine_lists` answer. Throws ProtocolError. */
export function parseEngineLists(raw: unknown): EngineLists {
  const x = rec(raw, "engine lists");
  if (!Array.isArray(x.lists)) throw new ProtocolError("lists must be an array");
  return { lists: x.lists.map(listStatus), compile_ms: absentOrInt(x.compile_ms, "compile_ms") };
}

export type PipeFact =
  | { kind: "welcome"; engine_version: string; session_id: number; status: EngineStatus }
  | { kind: "incompatible"; supported: [number, number] }
  | { kind: "refused"; message: string }
  | { kind: "unreachable"; message: string };

export interface EngineProbe {
  v: typeof ENGINE_PROBE_VERSION;
  service: ServiceFact;
  /** AdGuard for Windows' service (`Adguard Service`), read the same way: the pause offer and its undo follow it. */
  adguard: ServiceFact;
  pipe: PipeFact | null;
}

function pipeFact(raw: unknown): PipeFact {
  const p = rec(raw, "pipe");
  switch (p.kind) {
    case "welcome":
      return {
        kind: "welcome",
        engine_version: str(p.engine_version, "pipe.engine_version"),
        session_id: int(p.session_id, "pipe.session_id"),
        status: parseEngineStatus(p.status),
      };
    case "incompatible": {
      const range = Array.isArray(p.supported) && p.supported.length === 2 ? p.supported : null;
      if (!range) throw new ProtocolError("pipe.supported must be [min, max]");
      return { kind: "incompatible", supported: [int(range[0], "pipe.supported[0]"), int(range[1], "pipe.supported[1]")] };
    }
    case "refused":
    case "unreachable":
      return { kind: p.kind, message: str(p.message, "pipe.message") };
    default:
      throw new ProtocolError(`pipe.kind must be one of ${PIPE_KINDS.join(", ")}`);
  }
}

/** Validate an untrusted `engine_probe` answer. Throws ProtocolError. */
export function parseEngineProbe(raw: unknown): EngineProbe {
  const x = rec(raw, "engine probe");
  version(x, ENGINE_PROBE_VERSION, "engine probe");
  return {
    v: ENGINE_PROBE_VERSION,
    service: oneOf(x.service, SERVICE_FACTS, "service"),
    adguard: oneOf(x.adguard, SERVICE_FACTS, "adguard"),
    pipe: x.pipe === null ? null : pipeFact(x.pipe),
  };
}

/**
 * An app's icon (Rust `icons::AppIcon`, command `app_icon`): PNG bytes,
 * base64, at 32 px (x1) and 64 px (x2, HiDPI). Fetched per app, never part
 * of a snapshot.
 */
export interface AppIcon {
  x1: string;
  x2: string;
}

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * An icon answer, or null for "no icon" and for anything malformed: an icon
 * is decoration, so a bad one shows the monogram instead of an error.
 */
export function parseAppIcon(x: unknown): AppIcon | null {
  if (!isRec(x)) return null;
  const { x1, x2 } = x;
  return typeof x1 === "string" && typeof x2 === "string" && BASE64.test(x1) && BASE64.test(x2) ? { x1, x2 } : null;
}

/** Validate an untrusted value as a v1 Snapshot. Throws ProtocolError. */
export function parseSnapshot(x: unknown): Snapshot {
  if (!isRec(x)) throw new ProtocolError("snapshot must be an object");
  if (x.v !== PROTOCOL_VERSION) {
    throw new ProtocolError(`version ${String(x.v)} is not ${PROTOCOL_VERSION}`);
  }
  const t = int(x.t, "t");
  if (!Array.isArray(x.processes)) throw new ProtocolError("processes must be an array");
  if (!Array.isArray(x.flows)) throw new ProtocolError("flows must be an array");

  const processes = x.processes.map((p, i): ProcessInfo => {
    const w = `processes[${i}]`;
    if (!isRec(p)) throw new ProtocolError(`${w} must be an object`);
    return {
      pid: int(p.pid, `${w}.pid`),
      exe: strOrNull(p.exe, `${w}.exe`),
      name: str(p.name, `${w}.name`),
      product: strOrNull(p.product, `${w}.product`),
    };
  });

  const flows = x.flows.map((f, i): Flow => {
    const w = `flows[${i}]`;
    if (!isRec(f)) throw new ProtocolError(`${w} must be an object`);
    return {
      pid: int(f.pid, `${w}.pid`),
      proto: oneOf(f.proto, PROTOS, `${w}.proto`),
      family: oneOf(f.family, FAMILIES, `${w}.family`),
      local: endpoint(f.local, `${w}.local`),
      remote: f.remote === null ? null : endpoint(f.remote, `${w}.remote`),
      state: oneOf(f.state, FLOW_STATES, `${w}.state`),
    };
  });

  return { v: PROTOCOL_VERSION, t, processes, flows };
}
