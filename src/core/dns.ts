/**
 * DNS filtering, the pure part: the settings keys it owns, the upstream
 * address rule, the store slice and what the UI derives from it.
 *
 * DNS filtering is system wide. Every Windows lookup reaches a DNS proxy
 * through the DNS Client service, so the proxy cannot tell which app asked:
 * nothing here, and no copy built on it, may claim per-app blocking.
 *
 * The slice has one writer, the DNS controller (src/data/dns-controller.ts).
 */
import type { DnsCounters, DnsStatus, SelfCheck, SystemDnsState } from "@/data/protocol";
import type { SettingKey } from "./settings/registry";

/** The data switch that runs the filter. UI reads it from here, never spelled out. */
export const DNS_SWITCH = "filtering.dns" satisfies SettingKey;
/** The data switch that points Windows at the filter (the one system write). */
export const SYSTEM_DNS_SWITCH = "filtering.systemDns" satisfies SettingKey;
/** Upstream servers handed to dns_start. */
export const UPSTREAMS_KEY = "filtering.upstreams" satisfies SettingKey;

/** How often dns_status is read while the filter runs. */
export const DNS_POLL_MS = 2000;

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isPort(s: string): boolean {
  if (!/^\d{1,5}$/.test(s)) return false;
  const n = Number(s);
  return n >= 1 && n <= 65535;
}

function isV6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || !s.includes(":")) return false;
  const dbl = s.split("::").length - 1;
  if (dbl > 1) return false;
  const groups = s.split(":").filter((g) => g !== "");
  const tailV4 = groups.length > 0 && groups[groups.length - 1].includes(".");
  if (tailV4 && !V4.test(groups[groups.length - 1])) return false;
  const hex = tailV4 ? groups.slice(0, -1) : groups;
  if (!hex.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  const width = hex.length + (tailV4 ? 2 : 0);
  return dbl === 1 ? width < 8 : width === 8;
}

/**
 * An upstream as dns_start accepts it (src-tauri/src/dns/commands.rs
 * parse_upstream): an IPv4 or IPv6 address, optionally with a port as
 * `1.1.1.1:53` or `[2606:4700::1111]:53`. Names are refused: resolving a
 * resolver's name would need DNS.
 */
export function isUpstream(raw: string): boolean {
  const s = raw.trim();
  if (V4.test(s) || isV6(s)) return true;
  const v4port = s.match(/^([\d.]+):(\d+)$/);
  if (v4port) return V4.test(v4port[1]) && isPort(v4port[2]);
  const v6port = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6port) return isV6(v6port[1]) && (v6port[2] === undefined || isPort(v6port[2]));
  return false;
}

export type DnsBusy = "start" | "check" | "stop" | "point" | "restore";

export interface DnsSlice {
  /** Newest dns_status answer; null before the first read. */
  status: DnsStatus | null;
  /** Self check of the current run; null until one ran. */
  check: SelfCheck | null;
  /** Windows DNS per active adapter; null before the first read or when it cannot be read. */
  system: SystemDnsState | null;
  /** An AdGuard process is running (it intercepts lookups itself). */
  adguard: boolean;
  /** The action in flight, if any. */
  busy: DnsBusy | null;
  /** Newest failed action or read, cleared by the next good one. */
  error: string | null;
  /** Quit was asked while Windows points at Sieve: the window asks how to leave. */
  quitAsked: boolean;
}

export const EMPTY_DNS: DnsSlice = {
  status: null,
  check: null,
  system: null,
  adguard: false,
  busy: null,
  error: null,
  quitAsked: false,
};

export type DnsPhase = "off" | "starting" | "checking" | "running" | "stopping" | "error";

/** What the DNS card says about the filter, derived, never stored. */
export function dnsPhase(d: DnsSlice): DnsPhase {
  if (d.busy === "start") return "starting";
  if (d.busy === "check") return "checking";
  if (d.busy === "stop") return "stopping";
  if (d.status?.running) return "running";
  if (d.error !== null) return "error";
  return "off";
}

/** The filter answers lookups now. Only then may copy say "blocked". */
export function isFiltering(d: Pick<DnsSlice, "status">): boolean {
  return d.status?.running === true;
}

/** Blocked share of all lookups, 0 to 1; null before the first lookup. */
export function blockRate(c: DnsCounters): number | null {
  return c.queries === 0 ? null : c.blocked / c.queries;
}

/** Leaving Sieve must be asked about: Windows points at it (or a backup says Sieve pointed it). */
export function mustAskBeforeQuit(system: SystemDnsState | null): boolean {
  return system !== null && (system.pointed || system.backup);
}

/** The failed checks of a self check, in words: "doubleclick.net: expected NOERROR 0.0.0.0 (blocked), got no answer". */
export function failedChecks(c: SelfCheck): string {
  const bad = c.checks.filter((x) => !x.pass);
  if (bad.length === 0) return "no check ran";
  return bad.map((x) => `${x.name || "blocked name"}: expected ${x.expect}, got ${x.got}`).join("; ");
}

/** Lookups go nowhere unless Sieve answers them: Windows points at loopback and Sieve made the backup. */
export function needsProxyAtStart(system: SystemDnsState | null): boolean {
  return system !== null && system.pointed && system.backup;
}
