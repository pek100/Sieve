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
// Windows DNS, read only (the safety net). Mirror of src-tauri/src/windns.rs;
// wire names are Rust's snake_case. Fixture: src/data/fixtures/windows-dns-v1.json
// (Rust reads it too).

export const WINDOWS_DNS_VERSION = 1 as const;

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
 * runs. `status` is the engine's `sieve-ipc` Status (protocol 2, fixture
 * `engine-ipc-v2.json`). v2: the status carries the policy, the blocker, the
 * split tunnels and the engine's counters; the probe also reads AdGuard's
 * service state (`adguard`), for the pause offer.
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

export interface EnginePolicy {
  revision: number;
  engine: boolean;
}

export interface EngineCounters {
  flows: number;
  attributed: number;
  own_refused: number;
  dns_answers: number;
  packets_in: number;
  packets_out: number;
  not_unicast: number;
}

export interface EngineStatus {
  filtering: boolean;
  routes_up: boolean;
  flows: number;
  decrypting: boolean;
  last_error: string | null;
  policy: EnginePolicy;
  blocker: EngineBlocker | null;
  split_tunnels: string[];
  counters: EngineCounters;
  /** Absent until the engine holds compiled lists, and from an older engine. */
  filter?: FilterFacts;
}

/** One filter list as the engine compiled it (sieve-ipc `ListFact`; the catalogue stays in Rust). */
export interface ListFact {
  id: string;
  title: string;
  homepage: string;
  /** The list's own `! Version:`, when it has one. */
  version: string | null;
  applied: number;
  skipped: number;
}

/** What the engine filters with (sieve-ipc `FilterFacts`). */
export interface FilterFacts {
  lists: ListFact[];
  /** The resource library's pin, when one is loaded. */
  resource_pin: string | null;
}

const COUNTER_KEYS = ["flows", "attributed", "own_refused", "dns_answers", "packets_in", "packets_out", "not_unicast"] as const;

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

function filterFacts(raw: unknown): FilterFacts {
  const f = rec(raw, "status.filter");
  if (!Array.isArray(f.lists)) throw new ProtocolError("filter.lists must be an array");
  return {
    lists: f.lists.map((item, i) => {
      const w = `filter.lists[${i}]`;
      const l = rec(item, w);
      return {
        id: str(l.id, `${w}.id`),
        title: str(l.title, `${w}.title`),
        homepage: str(l.homepage, `${w}.homepage`),
        version: strOrNull(l.version ?? null, `${w}.version`),
        applied: int(l.applied, `${w}.applied`),
        skipped: int(l.skipped, `${w}.skipped`),
      };
    }),
    resource_pin: strOrNull(f.resource_pin ?? null, "filter.resource_pin"),
  };
}

/** Validate an untrusted engine Status (sieve-ipc). Throws ProtocolError. */
export function parseEngineStatus(raw: unknown): EngineStatus {
  const s = rec(raw, "status");
  const p = rec(s.policy, "status.policy");
  const c = rec(s.counters, "status.counters");
  return {
    filtering: bool(s.filtering, "status.filtering"),
    routes_up: bool(s.routes_up, "status.routes_up"),
    flows: int(s.flows, "status.flows"),
    decrypting: bool(s.decrypting, "status.decrypting"),
    last_error: strOrNull(s.last_error, "status.last_error"),
    policy: { revision: int(p.revision, "policy.revision"), engine: bool(p.engine, "policy.engine") },
    blocker: s.blocker === null ? null : blocker(s.blocker),
    split_tunnels: strings(s.split_tunnels, "status.split_tunnels"),
    counters: Object.fromEntries(COUNTER_KEYS.map((k) => [k, int(c[k], `counters.${k}`)])) as unknown as EngineCounters,
    ...(s.filter === undefined || s.filter === null ? {} : { filter: filterFacts(s.filter) }),
  };
}

// ---------------------------------------------------------------------------
// The filtering log. `LogRow` and `LogOutcome` mirror sieve-ipc; the envelope is
// `engine_log_tail` (src-tauri/src/engine.rs). Fixture:
// src/data/fixtures/engine-log-v1.json.

export const LOG_TAIL_VERSION = 1 as const;
/** sieve-ipc `LogOutcome` kinds, in declaration order. */
export const LOG_OUTCOMES = ["blocked", "redirected", "params_removed", "hidden", "scriptlets", "passed", "not_decrypted"] as const;

export type LogOutcome =
  | { kind: "blocked" }
  | { kind: "redirected" }
  | { kind: "params_removed" }
  | { kind: "hidden"; elements: number }
  | { kind: "scriptlets"; count: number }
  | { kind: "passed"; reason: string }
  | { kind: "not_decrypted"; reason: string };

export interface LogRow {
  id: number;
  /** ms since the Unix epoch, the engine's clock. */
  t: number;
  flow_id: number;
  pid: number | null;
  exe: string | null;
  session: number | null;
  /** sieve-ipc `FlowKind`: tls, http, quic, dns or other. */
  kind: string;
  /** The name, else the remote IP. */
  host: string;
  remote: string;
  /** Null on a host-level row. */
  url: string | null;
  request_type: string | null;
  outcome: LogOutcome;
  rule: string | null;
  /** A catalogue id, or "user". */
  list: string | null;
}

/** A row and its place in the app's own count, which survives an engine restart. */
export interface LogEntry {
  seq: number;
  row: LogRow;
}

export interface LogTail {
  v: typeof LOG_TAIL_VERSION;
  /** Ask for rows after this next time. */
  next: number;
  /** Rows the Rust ring dropped before this read could see them. */
  dropped: number;
  rows: LogEntry[];
  /** Rows of this answer that could not be read. */
  skipped: number;
}

const isCount = (x: unknown): x is number => typeof x === "number" && Number.isInteger(x) && x >= 0;
const optCount = (x: unknown): number | null => (isCount(x) ? x : null);
const optStr = (x: unknown): string | null => (typeof x === "string" ? x : null);

function logOutcome(raw: unknown): LogOutcome | null {
  if (!isRec(raw)) return null;
  switch (raw.kind) {
    case "blocked":
    case "redirected":
    case "params_removed":
      return { kind: raw.kind };
    case "hidden":
      return isCount(raw.elements) ? { kind: "hidden", elements: raw.elements } : null;
    case "scriptlets":
      return isCount(raw.count) ? { kind: "scriptlets", count: raw.count } : null;
    case "passed":
    case "not_decrypted":
      return typeof raw.reason === "string" ? { kind: raw.kind, reason: raw.reason } : null;
    default:
      return null;
  }
}

/** One row, or null when it has no seq, time, host or readable outcome. Optional fields default to null. */
function logEntry(raw: unknown): LogEntry | null {
  if (!isRec(raw) || !isCount(raw.seq) || !isRec(raw.row)) return null;
  const r = raw.row;
  const outcome = logOutcome(r.outcome);
  if (!isCount(r.t) || typeof r.host !== "string" || r.host === "" || outcome === null) return null;
  return {
    seq: raw.seq,
    row: {
      id: optCount(r.id) ?? raw.seq,
      t: r.t,
      flow_id: optCount(r.flow_id) ?? raw.seq,
      pid: optCount(r.pid),
      exe: optStr(r.exe),
      session: optCount(r.session),
      kind: optStr(r.kind) ?? "other",
      host: r.host,
      remote: optStr(r.remote) ?? "",
      url: optStr(r.url),
      request_type: optStr(r.request_type),
      outcome,
      rule: optStr(r.rule),
      list: optStr(r.list),
    },
  };
}

/**
 * Validate an untrusted `engine_log_tail` answer. A wrong version or a
 * non-array throws ProtocolError; one bad row is skipped and counted, so it
 * never empties a batch.
 */
export function parseLogTail(raw: unknown): LogTail {
  const x = rec(raw, "log tail");
  version(x, LOG_TAIL_VERSION, "log tail");
  if (!Array.isArray(x.rows)) throw new ProtocolError("log tail rows must be an array");
  const rows = x.rows.map(logEntry).filter((e): e is LogEntry => e !== null);
  const newest = rows.at(-1)?.seq ?? 0;
  return {
    v: LOG_TAIL_VERSION,
    next: isCount(x.next) ? x.next : newest,
    dropped: isCount(x.dropped) ? x.dropped : 0,
    rows,
    skipped: x.rows.length - rows.length,
  };
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
