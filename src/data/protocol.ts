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
// src-tauri/src/dns/probe.rs (dns_self_check) and src-tauri/src/sysdns
// (system_dns_state). Wire names are Rust's snake_case. Fixtures:
// src/data/fixtures/dns-status-v3.json, system-dns-v1.json (Rust reads them too).

export const DNS_STATUS_VERSION = 3 as const;
export const SYSTEM_DNS_VERSION = 1 as const;

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

export interface FamilyDns {
  /** Servers in force, in order. */
  servers: string[];
  /** True when the servers come from DHCP (or the adapter's defaults), false when set by hand. */
  dhcp: boolean;
}

export interface InterfaceDns {
  alias: string;
  index: number;
  v4: FamilyDns;
  v6: FamilyDns;
  /** IPv4 DNS is exactly 127.0.0.1 and IPv6 DNS exactly ::1. */
  uses_sieve: boolean;
}

export interface SystemDnsState {
  v: typeof SYSTEM_DNS_VERSION;
  /** Active (up, not loopback) adapters. */
  interfaces: InterfaceDns[];
  /** Some active adapter sends lookups to a loopback address. */
  pointed: boolean;
  /** Sieve's backup of the DNS before it pointed Windows here exists. */
  backup: boolean;
  /** Folder of the backup and restore-dns.ps1. */
  backup_dir: string | null;
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

function family(x: unknown, where: string): FamilyDns {
  const r = rec(x, where);
  return { servers: strings(r.servers, `${where}.servers`), dhcp: bool(r.dhcp, `${where}.dhcp`) };
}

/** Validate an untrusted `system_dns_state` answer. Throws ProtocolError. */
export function parseSystemDns(raw: unknown): SystemDnsState {
  const x = rec(raw, "system dns");
  version(x, SYSTEM_DNS_VERSION, "system dns");
  if (!Array.isArray(x.interfaces)) throw new ProtocolError("interfaces must be an array");
  return {
    v: SYSTEM_DNS_VERSION,
    interfaces: x.interfaces.map((it, i) => {
      const r = rec(it, `interfaces[${i}]`);
      const w = `interfaces[${i}]`;
      return {
        alias: str(r.alias, `${w}.alias`),
        index: int(r.index, `${w}.index`),
        v4: family(r.v4, `${w}.v4`),
        v6: family(r.v6, `${w}.v6`),
        uses_sieve: bool(r.uses_sieve, `${w}.uses_sieve`),
      };
    }),
    pointed: bool(x.pointed, "pointed"),
    backup: bool(x.backup, "backup"),
    backup_dir: strOrNull(x.backup_dir, "backup_dir"),
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
