/**
 * An encrypted DNS upstream as `filtering.upstreams` holds it: DNS over HTTPS
 * (`https://host[:port]/path`), DNS over TLS (`tls://host[:port]`) or DNS over
 * QUIC (`quic://host[:port]`). Nothing else: the engine sends no plain DNS, so
 * a bare address is not an upstream (plan 1.4).
 */
export const UPSTREAM_KINDS = ["doh", "dot", "doq"] as const;
export type UpstreamKind = (typeof UPSTREAM_KINDS)[number];

export interface Upstream {
  kind: UpstreamKind;
  host: string;
  port: number | null;
  /** The DoH template's path; null for DoT and DoQ. */
  path: string | null;
}

const MAX_PORT = 65535;
/** A name or an IPv4 address, or an IPv6 address in brackets. No userinfo: `@` is not in the class. */
const HOST = "([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\\[[0-9A-Fa-f:.]+\\])";
const PORT = "(?::(\\d{1,5}))?";
const DOH = new RegExp(`^https://${HOST}${PORT}(/[^\\s?#]*)$`);
const DOT = new RegExp(`^tls://${HOST}${PORT}$`);
const DOQ = new RegExp(`^quic://${HOST}${PORT}$`);

const FORMS: readonly (readonly [UpstreamKind, RegExp])[] = [
  ["doh", DOH],
  ["dot", DOT],
  ["doq", DOQ],
];

/** The upstream `raw` names, or null when it is not exactly one of the three forms. */
export function parseUpstream(raw: string): Upstream | null {
  for (const [kind, form] of FORMS) {
    const m = form.exec(raw);
    if (!m) continue;
    const port = m[2] === undefined ? null : Number(m[2]);
    if (port !== null && (port < 1 || port > MAX_PORT)) return null;
    return { kind, host: m[1], port, path: m[3] ?? null };
  }
  return null;
}
