/**
 * DNS filtering, the pure part: the settings keys it owns, the upstream
 * address rule, the store slice and what the UI derives from it.
 *
 * DNS filtering is system wide. Every Windows lookup reaches a DNS proxy
 * through the DNS Client service, so the proxy cannot tell which app asked:
 * nothing here, and no copy built on it, may claim per-app blocking.
 *
 * Sieve never points Windows DNS at the filter (docs/conventions.md, "Sieve
 * off means a normal network"), so today it filters only lookups sent to
 * 127.0.0.1:53 or [::1]:53 directly. `strandedAdapters` is the read-only
 * safety net for machines that still point there.
 *
 * The slice has one writer, the DNS controller (src/data/dns-controller.ts).
 */
import type { DnsCheck, DnsCounters, DnsStatus, SelfCheck, WindowsDns } from "@/data/protocol";
import type { SettingKey } from "./settings/registry";

/** The data switch that runs the filter. UI reads it from here, never spelled out. */
export const DNS_SWITCH = "filtering.dns" satisfies SettingKey;
/** Upstream servers handed to dns_start. */
export const UPSTREAMS_KEY = "filtering.upstreams" satisfies SettingKey;

/** How often dns_status is read while the filter runs. */
export const DNS_POLL_MS = 2000;
/** How often Windows DNS is read (read only) for the safety net, from startup on. */
export const WINDOWS_DNS_POLL_MS = 30_000;

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

export type DnsBusy = "start" | "check" | "stop" | "pass";

export interface DnsSlice {
  /** Newest dns_status answer; null before the first read. */
  status: DnsStatus | null;
  /** Self check of the current run; null until one ran. */
  check: SelfCheck | null;
  /** Windows DNS servers per active adapter (read only); null before the first good read. */
  windows: WindowsDns | null;
  /** An AdGuard process is running (it intercepts lookups itself). */
  adguard: boolean;
  /** The action in flight, if any. */
  busy: DnsBusy | null;
  /** Newest failed action or read, cleared by the next good one. */
  error: string | null;
}

export const EMPTY_DNS: DnsSlice = {
  status: null,
  check: null,
  windows: null,
  adguard: false,
  busy: null,
  error: null,
};

/** `paused`: running in pass-through (the global Sieving switch is off): it answers, forwards everything, blocks nothing. */
export type DnsPhase = "off" | "starting" | "checking" | "running" | "paused" | "stopping" | "error";

/** What the DNS card says about the filter, derived, never stored. */
export function dnsPhase(d: DnsSlice): DnsPhase {
  if (d.busy === "start") return "starting";
  if (d.busy === "check") return "checking";
  if (d.busy === "stop") return "stopping";
  if (d.status?.running) return d.status.pass_through ? "paused" : "running";
  if (d.error !== null) return "error";
  return "off";
}

/** The filter answers lookups and blocks now (running, not passing through). Only then may copy say "blocked". */
export function isFiltering(d: Pick<DnsSlice, "status">): boolean {
  return d.status?.running === true && !d.status.pass_through;
}

/** Blocked share of all lookups, 0 to 1; null before the first lookup. */
export function blockRate(c: DnsCounters): number | null {
  return c.queries === 0 ? null : c.blocked / c.queries;
}

/** Where the self check's full detail is shown (the DNS card in Settings). */
export const CHECK_DETAILS_AT = "Settings > Filtering";

/** A failed check in plain words, without the technical reply. */
function failureReason(c: DnsCheck): string {
  const silent = c.got.startsWith("no answer");
  switch (c.kind) {
    case "rules":
      return "no filter list is loaded";
    case "canary":
      return silent ? "the test name got no answer" : "the test name was not blocked";
    case "resolve":
      return silent ? "a normal name got no answer" : "a normal name did not resolve";
    case "call":
      return "the check could not run";
  }
}

/**
 * Where and why a self check failed, short and plain, each reason once with
 * the listeners it failed on: `on 127.0.0.1:53 and [::1]:53 (the test name
 * got no answer)`. The technical replies are `checkDetails`.
 */
export function checkFailure(c: SelfCheck): string {
  const groups = new Map<string, string[]>();
  for (const x of c.checks) {
    if (x.pass) continue;
    const servers = groups.get(failureReason(x)) ?? [];
    if (x.server !== "" && !servers.includes(x.server)) servers.push(x.server);
    groups.set(failureReason(x), servers);
  }
  if (groups.size === 0) return "(no check ran)";
  return [...groups.entries()]
    .map(([reason, servers]) => (servers.length === 0 ? `(${reason})` : `on ${servers.join(" and ")} (${reason})`))
    .join("; ");
}

/** The DNS card's line for a failed self check (also the slice's `error` after one). */
export function checkFailedLine(c: SelfCheck): string {
  return `The self check failed ${checkFailure(c)}.`;
}

/** The failed checks' technical replies, one line each, identical lines once. */
export function checkDetails(c: SelfCheck): string[] {
  const lines = c.checks
    .filter((x) => !x.pass)
    .map((x) => `${x.server || "filter"}: ${x.name || x.kind} expected ${x.expect}, got ${x.got}`);
  return [...new Set(lines)];
}

/**
 * The loopback DNS servers an old Sieve build pointed Windows at, each with
 * the listen address Sieve's filter answers it on. Windows always asks port 53.
 */
export const LOOPBACK_DNS: ReadonlyMap<string, string> = new Map([
  ["127.0.0.1", "127.0.0.1:53"],
  ["::1", "[::1]:53"],
]);

/**
 * The safety net's decision, pure: the active adapters whose DNS servers
 * include 127.0.0.1 or ::1 while no Sieve DNS listener answers there. Each
 * such adapter's lookups go nowhere, so sites may not load. Sieve never
 * changes Windows DNS; it only says so.
 *
 * `windows` null (not read yet, or unreadable) is unknown, not "nothing
 * pointed": it decides nothing. A filter that runs answers on its `binds`
 * (pass-through included: it still answers). Names in Windows' order, once.
 */
export function strandedAdapters(windows: WindowsDns | null, status: DnsStatus | null): string[] {
  if (windows === null) return [];
  const answered = new Set(status?.running ? status.binds : []);
  const out: string[] = [];
  for (const a of windows.adapters) {
    const stranded = a.servers.some((s) => {
      const listen = LOOPBACK_DNS.get(s);
      return listen !== undefined && !answered.has(listen);
    });
    if (stranded && !out.includes(a.alias)) out.push(a.alias);
  }
  return out;
}

/**
 * The safety notice, word for word wherever it shows (Home banner, DNS card).
 * It points only to Windows' own network settings: the DNS filter is
 * unavailable until the engine replaces it, so turning it on is no way out.
 */
export const STRANDED_DNS_TEXT =
  "Windows is set to use Sieve for DNS, but nothing of Sieve's answers there, so sites may not load. Set DNS back to automatic in Windows network settings.";
