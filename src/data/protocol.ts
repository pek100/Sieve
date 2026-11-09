/**
 * Snapshot protocol v1 (primitive B1). Mirrored in src-tauri/src/protocol.rs.
 * Raw facts about the machine only, no judgement: which processes exist and
 * which sockets they own. Changing the shape bumps PROTOCOL_VERSION and the
 * fixture (src/data/fixtures/snapshot-v1.json) in the same commit.
 */
import { NO_UPDATE_NEWS } from "@/core/engine";
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

function intOrNull(x: unknown, where: string): number | null {
  return x === null ? null : int(x, where);
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
 * `src/data/fixtures/engine-probe-v3.json`): the filtering engine from
 * facts. `service` is the Windows service's state ("missing" when not
 * installed); `pipe` is the engine's own answer, asked only while the service
 * runs. `status` is the engine's `sieve-ipc` Status (protocol 3, fixture
 * `engine-ipc-v3.json`). The status carries the policy, the blocker, the
 * split tunnels and the engine's counters; the probe also reads AdGuard's
 * service state (`adguard`), for the pause offer. Fields protocol 3 added read
 * as their typed defaults when absent, so an older answer degrades, not throws.
 */
export const ENGINE_PROBE_VERSION = 3 as const;
export const SERVICE_FACTS = ["missing", "stopped", "starting", "stopping", "running", "other"] as const;
export type ServiceFact = (typeof SERVICE_FACTS)[number];
export const PIPE_KINDS = ["welcome", "incompatible", "refused", "unreachable"] as const;
/** `sieve-ipc` Blocker kinds, in declaration order. */
export const BLOCKER_KINDS = ["adguard", "vpn", "crash_loop", "setup"] as const;
/** `sieve-ipc` UpdateStatus kinds, in declaration order. */
export const UPDATE_KINDS = ["not_configured", "idle", "checking", "current", "available", "applying", "stale", "failed", "refused", "rolled_back"] as const;

/** Where signed updates stand, as the engine says it (plan 7.5). `version` is for reading only. */
export type EngineUpdate =
  | { kind: "not_configured" | "idle" | "checking" | "current" | "stale" }
  | { kind: "available" | "applying" | "rolled_back"; version: string }
  | { kind: "failed" | "refused"; message: string };

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
  /** `filtering.https`: hold a root certificate. Off removes it. */
  https: boolean;
  /** `filtering.content`: decrypted pages get cosmetics. The engine leaves it out while false, so absent is off. */
  content?: boolean;
  /** `filtering.dnsEncryption` off: the user chose plain DNS. The engine leaves it out while false, so absent is encrypted. */
  plain_dns?: boolean;
  /** `filtering.dnsClientCapture` off: Windows' own lookups are not caught. Sent only when off; the engine leaves it out while false, so absent is on. */
  skip_dns_capture?: boolean;
  /** `filtering.userRules`: rule lines, compiled untrusted beside `domain_lists`. */
  user_rules: string[];
  /** `filtering.exclusions`: sites never decrypted. Nothing decrypts before slice 6. */
  exclusions: string[];
  /** `filters.custom`: the user's own lists. The engine leaves it out while empty, so absent is none. */
  custom_lists?: EngineCustomList[];
  /** The `tracking.*` protections on, by name; only while HTTPS decryption is in force. Absent is none. */
  tracking?: string[];
}

/** One of the user's own lists (sieve-ipc `CustomList`); `url` null: imported from a file. */
export interface EngineCustomList {
  id: string;
  title: string;
  url: string | null;
  enabled: boolean;
}

/** The encrypted DNS resolvers the engine holds (sieve-ipc `DnsUpstreams`). */
export interface EngineDnsUpstreams {
  /** Raised on every change; 0 is the engine's default list. */
  revision: number;
  /** Tried in order. */
  upstreams: string[];
}

/** Validate an untrusted `dns_upstreams` answer. Throws ProtocolError. */
export function parseDnsUpstreams(raw: unknown): EngineDnsUpstreams {
  const d = rec(raw, "dns upstreams");
  return { revision: int(d.revision, "dns.revision"), upstreams: strings(d.upstreams, "dns.upstreams") };
}

/** `sieve-ipc` CertState and FirefoxTrust wire names, in declaration order. */
export const CERT_STATES = ["not_installed", "installed", "expires_soon", "removal_pending"] as const;
export type CertState = (typeof CERT_STATES)[number];
export const FIREFOX_TRUST = ["not_installed", "uses_windows", "not_using_windows"] as const;
export type FirefoxTrust = (typeof FIREFOX_TRUST)[number];

/** The `cert_status` message (`sieve-ipc` CertStatus, plan 8.1): facts the engine holds; `null` is a fact it does not have. */
export interface CertStatus {
  state: CertState;
  valid_until_ms: number | null;
  thumbprint: string | null;
  firefox: FirefoxTrust;
  last_rotation_ms: number | null;
  last_error: string | null;
}

/** Validate an untrusted `cert_status` answer, the one normalizer of this shape. Throws ProtocolError. */
export function parseCertStatus(raw: unknown): CertStatus {
  const c = rec(raw, "cert status");
  return {
    state: oneOf(c.state, CERT_STATES, "cert.state"),
    valid_until_ms: intOrNull(c.valid_until_ms, "cert.valid_until_ms"),
    thumbprint: strOrNull(c.thumbprint, "cert.thumbprint"),
    firefox: oneOf(c.firefox, FIREFOX_TRUST, "cert.firefox"),
    last_rotation_ms: intOrNull(c.last_rotation_ms, "cert.last_rotation_ms"),
    last_error: strOrNull(c.last_error, "cert.last_error"),
  };
}

/** `sieve-ipc` ExclusionScope wire names, in declaration order. */
export const EXCLUSION_SCOPES = ["browsers", "all"] as const;
export type ExclusionScope = (typeof EXCLUSION_SCOPES)[number];

/** One entry of the engine's `list:*` or `auto:*` layers (`sieve-ipc` ExclusionRow). */
export interface ExclusionRow {
  /** The pattern in the list grammar, with no `$app=`. */
  line: string;
  /** Lower-case exe file names; empty means every app. */
  apps: string[];
  /** A slug: `list:<id>`, `auto:pinning`, ... An unknown one still renders. */
  reason: string;
  /** When the engine first wrote it; null for a list's line. */
  created_ms: number | null;
  retries: number;
}

/** One page of `exclusions` (`sieve-ipc` EngineMessage::Exclusions). */
export interface ExclusionsPage {
  revision: number;
  rows: ExclusionRow[];
  total: number;
  next: number | null;
  scope: ExclusionScope;
  /** Full paths, lower case: the exes Windows declares as browsers. */
  browsers: string[];
  /** Rows that could not be read. */
  skipped: number;
}

/** One row, or null when it is broken: the rest of the list still renders. */
function exclusionRow(raw: unknown): ExclusionRow | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.line !== "string" || r.line === "" || typeof r.reason !== "string") return null;
  const apps = Array.isArray(r.apps) ? r.apps.filter((a): a is string => typeof a === "string") : [];
  const created = typeof r.created_ms === "number" && Number.isSafeInteger(r.created_ms) && r.created_ms >= 0 ? r.created_ms : null;
  const retries = typeof r.retries === "number" && Number.isSafeInteger(r.retries) && r.retries >= 0 ? r.retries : 0;
  return { line: r.line, apps, reason: r.reason, created_ms: created, retries };
}

/**
 * Validate an untrusted `exclusions` answer, the one normalizer of this shape: a
 * bad row is skipped and counted, like `parseLogTail`; a wrong shape throws.
 */
export function parseExclusionsPage(raw: unknown): ExclusionsPage {
  const p = rec(raw, "exclusions");
  if (!Array.isArray(p.rows)) throw new ProtocolError("exclusions.rows must be an array");
  const rows = p.rows.map(exclusionRow).filter((r): r is ExclusionRow => r !== null);
  return {
    revision: int(p.revision, "exclusions.revision"),
    rows,
    total: int(p.total, "exclusions.total"),
    next: intOrNull(p.next, "exclusions.next"),
    scope: oneOf(p.scope, EXCLUSION_SCOPES, "exclusions.scope"),
    browsers: strings(p.browsers, "exclusions.browsers"),
    skipped: p.rows.length - rows.length,
  };
}

/** One group of self-healing exclusions of one app (`sieve-ipc` HealNotice). */
export interface HealNotice {
  id: number;
  session: number;
  /** The exe's file name, lower case. */
  exe: string;
  /** The first few hosts; `total` counts them all. */
  hosts: string[];
  total: number;
  rev: number;
}

/** The `heal_notices` message. */
export interface HealNotices {
  /** This engine run. A new one starts `revision` and the ids over. */
  run: number;
  revision: number;
  exclusions_revision: number;
  notices: HealNotice[];
}

function healNotice(raw: unknown): HealNotice | null {
  if (raw === null || typeof raw !== "object") return null;
  const n = raw as Record<string, unknown>;
  const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (!count(n.id) || !count(n.session) || !count(n.total) || !count(n.rev) || typeof n.exe !== "string" || !Array.isArray(n.hosts)) return null;
  const hosts = n.hosts.filter((h): h is string => typeof h === "string");
  return hosts.length > 0 ? { id: n.id, session: n.session, exe: n.exe, hosts, total: Math.max(n.total, hosts.length), rev: n.rev } : null;
}

/** Validate an untrusted `heal_notices` answer. A bad notice is left out; a wrong shape throws. */
export function parseHealNotices(raw: unknown): HealNotices {
  const h = rec(raw, "heal notices");
  if (!Array.isArray(h.notices)) throw new ProtocolError("heal.notices must be an array");
  return {
    run: int(h.run, "heal.run"),
    revision: int(h.revision, "heal.revision"),
    exclusions_revision: int(h.exclusions_revision, "heal.exclusions_revision"),
    notices: h.notices.map(healNotice).filter((n): n is HealNotice => n !== null),
  };
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
  /** Absent until the engine holds compiled lists, and from an older engine. */
  filter?: FilterFacts;
  /** With encryption on, no encrypted DNS server has answered the last lookups. Absent is false. */
  dns_unreachable?: boolean;
  /** Whether Windows' own lookups are caught, while routes are up. Absent: routes down, or an older engine. */
  dns_capture?: DnsCapture;
  update: EngineUpdate;
}

/** sieve-ipc `CaptureReason`, in declaration order. */
export const CAPTURE_REASONS = ["tie", "ipv6_off", "no_answer", "no_ipv4", "failed"] as const;
export type CaptureReason = (typeof CAPTURE_REASONS)[number];

/** sieve-ipc `DnsCapture`: caught and proven, the user's off, or not caught and why. */
export type DnsCapture = { state: "working" } | { state: "off" } | { state: "not_caught"; reason: CaptureReason; adapter?: string; detail: string };

const withCapture = (c: DnsCapture | null): { dns_capture?: DnsCapture } => (c === null ? {} : { dns_capture: c });

/** A notice, as `dns_unreachable`: anything unexpected reads as nothing to say, never a refused Status. */
export function parseDnsCapture(raw: unknown): DnsCapture | null {
  if (typeof raw !== "object" || raw === null) return null;
  const c = raw as Record<string, unknown>;
  if (c.state === "working" || c.state === "off") return { state: c.state };
  if (c.state !== "not_caught" || typeof c.detail !== "string" || !(CAPTURE_REASONS as readonly unknown[]).includes(c.reason)) return null;
  return { state: "not_caught", reason: c.reason as CaptureReason, detail: c.detail, ...(typeof c.adapter === "string" ? { adapter: c.adapter } : {}) };
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
    https: orDefault(p.https, (v) => bool(v, "policy.https"), false),
    ...(p.content === undefined ? {} : { content: bool(p.content, "policy.content") }),
    ...(p.plain_dns === undefined ? {} : { plain_dns: bool(p.plain_dns, "policy.plain_dns") }),
    ...(p.skip_dns_capture === undefined ? {} : { skip_dns_capture: bool(p.skip_dns_capture, "policy.skip_dns_capture") }),
    user_rules: orDefault(p.user_rules, (v) => strings(v, "policy.user_rules"), []),
    exclusions: orDefault(p.exclusions, (v) => strings(v, "policy.exclusions"), []),
    ...(p.custom_lists === undefined ? {} : { custom_lists: customLists(p.custom_lists) }),
    ...(p.tracking === undefined ? {} : { tracking: strings(p.tracking, "policy.tracking") }),
  };
}

function customLists(raw: unknown): EngineCustomList[] {
  if (!Array.isArray(raw)) throw new ProtocolError("policy.custom_lists must be an array");
  return raw.map((v, i) => {
    const w = `custom_lists[${i}]`;
    const c = rec(v, w);
    return { id: str(c.id, `${w}.id`), title: str(c.title, `${w}.title`), url: strOrNull(c.url, `${w}.url`), enabled: bool(c.enabled, `${w}.enabled`) };
  });
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

/**
 * The update state. Unlike the rest of the Status it never refuses the
 * answer: updates are news, and a missing, partial or unknown one must not
 * take the Engine block's facts down with it. It reads as nothing to say.
 */
function engineUpdate(raw: unknown): EngineUpdate {
  if (!isRec(raw)) return NO_UPDATE_NEWS;
  const { kind, version, message } = raw;
  switch (kind) {
    case "idle":
    case "checking":
    case "current":
    case "stale":
    case "not_configured":
      return { kind };
    case "available":
    case "applying":
    case "rolled_back":
      return typeof version === "string" ? { kind, version } : NO_UPDATE_NEWS;
    case "failed":
    case "refused":
      return typeof message === "string" ? { kind, message } : NO_UPDATE_NEWS;
    default:
      return NO_UPDATE_NEWS;
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
    ...(s.filter === undefined || s.filter === null ? {} : { filter: filterFacts(s.filter) }),
    // A notice, like the update state: an odd value reads as nothing to say, never a refused Status.
    ...(s.dns_unreachable === true ? { dns_unreachable: true } : {}),
    ...withCapture(parseDnsCapture(s.dns_capture)),
    update: engineUpdate(s.update),
  };
}

// ---------------------------------------------------------------------------
// The filtering log. `LogRow` and `LogOutcome` mirror sieve-ipc; the envelope is
// `engine_log_tail` (src-tauri/src/engine.rs). Fixture:
// src/data/fixtures/engine-log-v1.json.

export const LOG_TAIL_VERSION = 1 as const;
/** sieve-ipc `LogOutcome` kinds, in declaration order. */
export const LOG_OUTCOMES = ["blocked", "redirected", "params_removed", "hidden", "scriptlets", "passed", "not_decrypted", "problem", "retried"] as const;

/** sieve-ipc `Signal`, in declaration order: what went wrong for a flow. */
export const SIGNALS = [
  "connect_refused",
  "connect_timeout",
  "unreachable",
  "connect_failed",
  "egress_failed",
  "connection_lost",
  "stall",
  "dns_unanswered",
  "app_refused_certificate",
  "blocked",
  "quic_refused",
  "handshake_abandoned",
  // What the Rust reader makes of a signal a newer engine sent that this build does not know.
  "unknown",
] as const;
export type Signal = (typeof SIGNALS)[number];
/** sieve-ipc `Cause`: who most likely caused it. The engine decides; the app only says it. */
export const CAUSES = ["sieve", "network", "unknown"] as const;
export type Cause = (typeof CAUSES)[number];
/** sieve-ipc `RetryHow`. */
export const RETRY_HOWS = ["next_address", "reconnect"] as const;
export type RetryHow = (typeof RETRY_HOWS)[number];

export type LogOutcome =
  | { kind: "blocked" }
  | { kind: "redirected" }
  | { kind: "params_removed" }
  | { kind: "hidden"; elements: number }
  | { kind: "scriptlets"; count: number }
  | { kind: "passed"; reason: string }
  | { kind: "not_decrypted"; reason: string }
  | { kind: "problem"; signal: Signal; cause: Cause }
  | { kind: "retried"; how: RetryHow; recovered: boolean };

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
  /** Present on a guest's flow, which has no process. `vm` null: its VM has no name. */
  forwarded?: { vm: string | null };
  /** What tracking protection changed in the request or its response; absent while nothing. */
  changes?: LogChange[];
}

/** sieve-ipc `LogChange`: `what` is a tracking protection's name (`Policy.tracking`), `count` how many things it changed. */
export interface LogChange {
  what: string;
  count: number;
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
    case "problem":
      return isOneOf(raw.signal, SIGNALS) && isOneOf(raw.cause, CAUSES) ? { kind: "problem", signal: raw.signal, cause: raw.cause } : null;
    case "retried":
      return isOneOf(raw.how, RETRY_HOWS) && typeof raw.recovered === "boolean" ? { kind: "retried", how: raw.how, recovered: raw.recovered } : null;
    default:
      return null;
  }
}

const isOneOf = <T extends string>(x: unknown, names: readonly T[]): x is T => typeof x === "string" && (names as readonly string[]).includes(x);

// ---------------------------------------------------------------------------
// Each app's recent problems (`issues`, sieve-ipc `AppIssues`). Local only.

export interface Problem {
  signal: Signal;
  cause: Cause;
  /** The name, else the remote IP; null for a lookup with no question read. */
  host: string | null;
  count: number;
  first_ms: number;
  last_ms: number;
}

export interface AppIssues {
  /** The app's `apps.levels` key, or a VM row's `vm:` key. */
  key: string;
  /** The exe's file name, lower case; null for a VM. */
  exe: string | null;
  session: number | null;
  /** When Sieve first saw the app since it last started routing. */
  since_ms: number;
  flows: number;
  retried: number;
  recovered: number;
  /** Newest first. */
  problems: Problem[];
}

export interface Issues {
  run: number;
  revision: number;
  /** Empty when nothing changed since the revision asked for. */
  apps: AppIssues[];
  dropped: number;
}

function problem(raw: unknown): Problem | null {
  if (!isRec(raw) || !isOneOf(raw.signal, SIGNALS) || !isOneOf(raw.cause, CAUSES) || !isCount(raw.count) || !isCount(raw.last_ms)) return null;
  return { signal: raw.signal, cause: raw.cause, host: optStr(raw.host), count: raw.count, first_ms: optCount(raw.first_ms) ?? raw.last_ms, last_ms: raw.last_ms };
}

/** One app, or null without a key or any readable problem. Counts default to 0. */
function appIssues(raw: unknown): AppIssues | null {
  if (!isRec(raw) || typeof raw.key !== "string" || raw.key === "" || !Array.isArray(raw.problems)) return null;
  const problems = raw.problems.map(problem).filter((p): p is Problem => p !== null);
  if (problems.length === 0) return null;
  return {
    key: raw.key,
    exe: optStr(raw.exe),
    session: optCount(raw.session),
    since_ms: optCount(raw.since_ms) ?? Math.min(...problems.map((p) => p.first_ms)),
    flows: optCount(raw.flows) ?? 0,
    retried: optCount(raw.retried) ?? 0,
    recovered: optCount(raw.recovered) ?? 0,
    problems,
  };
}

/** Validate an untrusted `issues` answer, the one normalizer of this shape. A bad app or problem is left out; a wrong shape throws. */
export function parseIssues(raw: unknown): Issues {
  const x = rec(raw, "issues");
  if (!Array.isArray(x.apps)) throw new ProtocolError("issues.apps must be an array");
  return {
    run: int(x.run, "issues.run"),
    revision: int(x.revision, "issues.revision"),
    apps: x.apps.map(appIssues).filter((a): a is AppIssues => a !== null),
    dropped: optCount(x.dropped) ?? 0,
  };
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
      ...(isRec(r.forwarded) ? { forwarded: { vm: optStr(r.forwarded.vm) } } : {}),
      ...logChanges(r.changes),
    },
  };
}

/** A row's tracking changes; a change that does not read is left out, never the row. Absent while none. */
function logChanges(raw: unknown): { changes?: LogChange[] } {
  if (!Array.isArray(raw)) return {};
  const changes = raw.filter((c): c is LogChange => isRec(c) && typeof c.what === "string" && c.what !== "" && isCount(c.count) && c.count > 0).map((c) => ({ what: c.what, count: c.count }));
  return changes.length > 0 ? { changes } : {};
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

/** `filter_catalogue` (src-tauri/src/filters.rs, the engine's catalogue::LISTS). Fixture: filter-lists-v1.json. */
export const FILTER_CATALOGUE_VERSION = 1 as const;
export const LIST_DEFAULTS = ["on", "off", "gated"] as const;

/** What compiling one list did. Absent (null on the list) is not zero: not loaded yet. */
export interface FilterReport {
  applied: number;
  skipped: number;
  /** The parser's reason to how many rules it skipped. */
  reasons: Record<string, number>;
}

/** What a list is for (catalogue `Kind`). */
export const LIST_KINDS = ["ads", "tracking", "annoyances", "security", "language"] as const;
export type ListKind = (typeof LIST_KINDS)[number];
/** The lowest profile that turns a list on (catalogue `Level`); `optional`: none does. */
export const LIST_LEVELS = ["minimal", "balanced", "strict", "optional"] as const;
export type ListLevel = (typeof LIST_LEVELS)[number];

/** What the engine says about a list's copy, laid over the catalogue. Null: it said nothing. */
export interface ListFetch {
  /** The last good download, ms since the epoch; null: no copy yet. */
  fetchedAtMs: number | null;
  /** Why the last attempt failed, in the engine's words; the last good copy stays in use. */
  lastError: string | null;
  /** In the engine's selection now. */
  enabled: boolean;
}

export interface FilterList {
  id: string;
  title: string;
  url: string;
  licence: string;
  default: (typeof LIST_DEFAULTS)[number];
  trusted: boolean;
  kind: ListKind;
  /** Null: the row did not say (an older build's), so no profile decides it. */
  level: ListLevel | null;
  /** What turning it on does, in plain words. */
  description: string;
  /** Primary language subtags of the sites it is for; empty for every site. */
  languages: readonly string[];
  report: FilterReport | null;
  /** Absent until the engine's report is laid over the catalogue. */
  fetch?: ListFetch | null;
}

export interface FilterCatalogue {
  v: typeof FILTER_CATALOGUE_VERSION;
  lists: FilterList[];
  /** Rows that could not be read, left out and said in a line. */
  dropped: number;
}

function filterReport(x: unknown): FilterReport | null {
  if (!isRec(x) || !isRec(x.reasons)) return null;
  const { applied, skipped } = x;
  const count = (n: unknown) => typeof n === "number" && Number.isInteger(n) && n >= 0;
  if (!count(applied) || !count(skipped)) return null;
  const reasons = Object.fromEntries(Object.entries(x.reasons).filter(([, n]) => count(n))) as Record<string, number>;
  return { applied: applied as number, skipped: skipped as number, reasons };
}

function filterList(x: unknown): FilterList | null {
  if (!isRec(x)) return null;
  const { id, title, url, licence, trusted } = x;
  if (typeof id !== "string" || id === "" || typeof title !== "string" || title === "") return null;
  if (!(LIST_DEFAULTS as readonly unknown[]).includes(x.default)) return null;
  // Rows from before kinds and levels (an older build's answer) read as an ad
  // list with no level: shown, outside every profile, never turned on or off by one.
  const pick = <T extends string, F>(v: unknown, of: readonly T[], fallback: F): T | F => ((of as readonly unknown[]).includes(v) ? (v as T) : fallback);
  return {
    id,
    title,
    url: typeof url === "string" ? url : "",
    licence: typeof licence === "string" ? licence : "",
    default: x.default as FilterList["default"],
    trusted: trusted === true,
    kind: pick(x.kind, LIST_KINDS, "ads"),
    level: pick(x.level, LIST_LEVELS, null),
    description: typeof x.description === "string" ? x.description : "",
    languages: Array.isArray(x.languages) ? x.languages.filter((l): l is string => typeof l === "string") : [],
    report: filterReport(x.report),
  };
}

/** `engine_list_rules`: the first rules of one list's copy that hold the search. */
export interface ListRules {
  id: string;
  lines: string[];
  matched: number;
  total: number;
}

export function parseListRules(raw: unknown): ListRules {
  const x = rec(raw, "list rules");
  return { id: str(x.id, "list rules.id"), lines: strings(x.lines, "list rules.lines"), matched: int(x.matched, "list rules.matched"), total: int(x.total, "list rules.total") };
}

/** `engine_list_import`: the engine kept the picked file's list. Null: the person closed the picker. */
export interface ListImported {
  /** The file's name, the list's name until the person gives another. */
  name: string;
  rules: number;
  skipped: number;
}

export function parseListImported(raw: unknown): ListImported | null {
  if (raw === null) return null;
  const x = rec(raw, "list import");
  return { name: str(x.name, "list import.name"), rules: int(x.rules, "list import.rules"), skipped: int(x.skipped, "list import.skipped") };
}

/**
 * The one normaliser of the catalogue. A wrong version or a missing list array
 * throws (the block's error state); a malformed row is dropped and counted, a
 * bad report reads null.
 */
export function parseFilterCatalogue(raw: unknown): FilterCatalogue {
  if (!isRec(raw)) throw new ProtocolError("filter catalogue must be an object");
  if (raw.v !== FILTER_CATALOGUE_VERSION) throw new ProtocolError(`filter catalogue version ${String(raw.v)} is not ${FILTER_CATALOGUE_VERSION}`);
  if (!Array.isArray(raw.lists)) throw new ProtocolError("filter catalogue lists must be an array");
  const lists = raw.lists.map(filterList).filter((l): l is FilterList => l !== null);
  return { v: FILTER_CATALOGUE_VERSION, lists, dropped: raw.lists.length - lists.length };
}

/** One line `rule_check` refused. `line` counts from 1; `reason` is the parser's own words. */
export interface RuleProblem {
  line: number;
  reason: string;
}

export function parseRuleProblems(raw: unknown): RuleProblem[] {
  if (!Array.isArray(raw)) throw new ProtocolError("rule check must be an array");
  return raw.map((p, i) => {
    if (!isRec(p)) throw new ProtocolError(`rule check[${i}] must be an object`);
    return { line: int(p.line, `rule check[${i}].line`), reason: str(p.reason, `rule check[${i}].reason`) };
  });
}

/** `lock_status` and `lock_verify` (src-tauri/src/lock.rs). Neither carries a hash. */
export const LOCK_STATES = ["none", "set", "unreadable"] as const;

export interface LockStatus {
  state: (typeof LOCK_STATES)[number];
  retry_after_secs: number;
}

export interface LockVerdict {
  ok: boolean;
  retry_after_secs: number;
}

const waitSecs = (x: unknown) => (typeof x === "number" && Number.isFinite(x) && x > 0 ? x : 0);

/** Anything unknown reads `unreadable`: settings stay locked, never open. */
export function parseLockStatus(raw: unknown): LockStatus {
  const state = isRec(raw) && (LOCK_STATES as readonly unknown[]).includes(raw.state) ? (raw.state as LockStatus["state"]) : "unreadable";
  return { state, retry_after_secs: isRec(raw) ? waitSecs(raw.retry_after_secs) : 0 };
}

/** Only an explicit `ok: true` opens anything. */
export function parseLockVerdict(raw: unknown): LockVerdict {
  return { ok: isRec(raw) && raw.ok === true, retry_after_secs: isRec(raw) ? waitSecs(raw.retry_after_secs) : 0 };
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
