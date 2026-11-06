/**
 * An encrypted DNS upstream as `filtering.upstreams` holds it: DNS over HTTPS
 * (`https://host[:port][/path][?query]`), DNS over TLS (`tls://host[:port][/]`)
 * or DNS over QUIC (`quic://host[:port][/]`). Nothing else: the engine sends no
 * plain DNS, so a bare address is not an upstream (plan 1.4).
 *
 * This is the same grammar as the engine's `Upstream` in `dns/upstream.rs`, and
 * built the same way: the checks below, then the WHATWG URL parser the `url`
 * crate also implements. `tests/laws/upstream-grammar.test.ts` and the engine's
 * `tests/upstream_grammar.rs` hold both to one table.
 */
export const UPSTREAM_KINDS = ["doh", "dot", "doq"] as const;
export type UpstreamKind = (typeof UPSTREAM_KINDS)[number];

/** How many upstreams the engine takes. The grammar table holds this and the engine's own limit to one number. */
export const MAX_UPSTREAMS = 8;

export interface Upstream {
  kind: UpstreamKind;
  /** As the URL parser gives it; an IPv6 address keeps its brackets. */
  host: string;
  port: number | null;
  /** The DoH request target, with its query; null for DoT and DoQ. */
  path: string | null;
}

const KINDS = new Map<string, UpstreamKind>([
  ["https:", "doh"],
  ["tls:", "dot"],
  ["quic:", "doq"],
]);

/** URL parsers repair these and would select a different endpoint than the text names. */
const REPAIRED = /[\p{White_Space}\p{Cc}\\]/u;
/** The same repair: `https:x` and `https:///x` both parse to the host `x`. */
const NAMES_A_HOST = /^[^:]*:\/\/[^/]/;
const LABEL = /^[A-Za-z0-9_-]{1,63}$/;
const NAME_MAX = 253;

/** The engine's `sni::host_name`. */
function isHostName(raw: string): boolean {
  const name = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  return name.length > 0 && name.length <= NAME_MAX && name.split(".").every((label) => LABEL.test(label));
}

/** The upstream `raw` names, or null when it is not exactly one of the three forms. */
export function parseUpstream(raw: string): Upstream | null {
  // The URL API hides an empty `#` or `?`, which the raw text still shows.
  if (REPAIRED.test(raw) || !NAMES_A_HOST.test(raw) || raw.includes("#")) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const kind = KINDS.get(url.protocol);
  if (kind === undefined || url.username !== "" || url.password !== "" || url.port === "0") return null;
  if (!url.hostname.startsWith("[") && !isHostName(url.hostname)) return null;
  if (kind !== "doh" && ((url.pathname !== "" && url.pathname !== "/") || raw.includes("?"))) return null;
  return {
    kind,
    host: url.hostname,
    port: url.port === "" ? null : Number(url.port),
    path: kind === "doh" ? url.pathname + url.search : null,
  };
}

const SCHEMES: Record<UpstreamKind, string> = { doh: "https", dot: "tls", doq: "quic" };
const DEFAULT_PORTS: Record<UpstreamKind, number> = { doh: 443, dot: 853, doq: 853 };
/** Where a DoH resolver answers: `https://host/` is almost never its path. */
const DOH_PATH = "/dns-query";
/** A bare IPv6 address: only hex digits, colons and dots, with two colons at least. */
const BARE_IPV6 = /^(?=[^:]*:[^:]*:)[0-9A-Fa-f:.]+$/;
/** Text that already says its scheme: `x://`, or a colon that does not start a port. */
const WRITTEN = /^[^/:[]+:(?!\d)|:\/\//;

/** What the user typed, as an address, with its parsed form. */
export interface ComposedUpstream {
  address: string;
  upstream: Upstream;
}

/**
 * The address `typed` means under `kind`, or null when the grammar refuses it. A
 * URL is taken as written, so a pasted one keeps its own kind whatever is selected.
 * Otherwise the scheme comes from the kind, a bare IPv6 address gets its brackets,
 * and DoH with no path gets the usual one. `parseUpstream` decides either way.
 */
export function composeUpstream(kind: UpstreamKind, typed: string): ComposedUpstream | null {
  const bare = typed.trim();
  if (bare === "") return null;
  let address = typed;
  if (BARE_IPV6.test(bare)) address = `${SCHEMES[kind]}://[${bare}]`;
  else if (!WRITTEN.test(typed)) address = `${SCHEMES[kind]}://${bare}`;
  const parsed = parseUpstream(address);
  if (parsed === null) return null;
  if (address === typed || parsed.kind !== "doh" || /[/?]/.test(bare)) return { address, upstream: parsed };
  const withPath = `${address}${DOH_PATH}`;
  const upstream = parseUpstream(withPath);
  return upstream && { address: withPath, upstream };
}

/** One upstream's identity, as the engine compares a list for repeats: `tls://DNS.example` and `tls://dns.example:853` are one. */
export function upstreamIdentity(u: Upstream): string {
  const host = u.host.toLowerCase().replace(/\.$/, "");
  return `${u.kind} ${host} ${u.port ?? DEFAULT_PORTS[u.kind]} ${u.path ?? ""}`;
}

/**
 * The line that says what the engine holds against what is set, or null when the
 * engine cannot be asked (the Engine block says why). A different order counts as
 * different: the order is the order they are tried in.
 */
export function upstreamReadback(want: readonly string[], held: readonly string[] | null | undefined): string | null {
  if (!Array.isArray(held) || held.length === 0) return null;
  const same = held.length === want.length && held.every((u, i) => u === want[i]);
  return same ? "The engine uses this list." : `The engine still uses: ${held.join(", ")}.`;
}
