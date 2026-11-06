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
