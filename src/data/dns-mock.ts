/**
 * Mock DNS source: a deterministic DNS filter and Windows DNS reads for the
 * browser, tests and e2e. Counters grow with every status read while the
 * filter runs (content depends on the read count and seed, never on the
 * clock). Addresses come from the documentation ranges only.
 *
 * Query string: ?dns=off|error (default off), ?adguard=1, ?pointed=1.
 * - off: nothing runs; starting works.
 * - error: starting fails because port 53 is taken.
 * - pointed: Windows' Wi-Fi adapter asks 127.0.0.1 and ::1 (left by an old
 *   Sieve build, or set by hand). Sieve never changes it; only then do
 *   lookups reach the filter, as on a real machine.
 */
import { DNS_STATUS_VERSION, WINDOWS_DNS_VERSION, type AdapterDns, type DnsStatus, type SelfCheck, type WindowsDns } from "./protocol";
import { hash01 } from "./prng";
import type { DnsSource } from "./dns-source";

export const DNS_SCENARIOS = ["off", "error"] as const;
export type DnsScenario = (typeof DNS_SCENARIOS)[number];

export interface MockDnsOptions {
  seed: number;
  scenario?: DnsScenario;
  adguard?: boolean;
  /** One adapter asks 127.0.0.1 and ::1 for DNS. */
  pointed?: boolean;
  /** Clock for started_at and fetched_at; content never depends on it. */
  now?: () => number;
}

export const MOCK_LIST_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
export const MOCK_PORT_BUSY =
  "cannot listen on 127.0.0.1:53: Only one usage of each socket address (protocol/network address/port) is normally permitted. (os error 10048)";
const BINDS = ["127.0.0.1:53", "[::1]:53"];
/** Rust's `rules::CANARY_NAME`, the self check's test name. */
export const MOCK_CANARY = "selfcheck.sieve.invalid";

/** Plausible ad and tracker domains, most blocked first (weights fall off). */
const DOMAINS = [
  "doubleclick.net",
  "googlesyndication.com",
  "app-measurement.com",
  "googleadservices.com",
  "adservice.google.com",
  "scorecardresearch.com",
  "ads.linkedin.com",
  "bat.bing.com",
  "connect.facebook.net",
  "pixel.wp.com",
  "adnxs.com",
  "criteo.com",
  "taboola.com",
  "outbrain.com",
];

/** Windows' own DNS: two active adapters. */
const OWN: readonly AdapterDns[] = [
  { alias: "Wi-Fi", index: 12, servers: ["192.0.2.53", "2001:db8::53"] },
  { alias: "Ethernet 2", index: 7, servers: ["198.51.100.53", "203.0.113.53"] },
];

/** ?pointed=1: the Wi-Fi adapter asks the loopback addresses. */
const POINTED: readonly AdapterDns[] = [{ ...OWN[0], servers: ["127.0.0.1", "::1"] }, OWN[1]];

/** An upstream as Rust reports it (SocketAddr display): port 53 added when absent. */
function socketAddr(raw: string): string {
  const u = raw.trim();
  if (u.startsWith("[")) return u.includes("]:") ? u : `${u}:53`;
  const colons = u.split(":").length - 1;
  if (colons === 0) return `${u}:53`;
  return colons === 1 ? u : `[${u}]:53`;
}

export function createMockDns(o: MockDnsOptions): DnsSource {
  const scenario = o.scenario ?? "off";
  const now = o.now ?? (() => Date.now());
  let running = false;
  let passThrough = false;
  let startedAt: number | null = null;
  let upstreams: string[] = [];
  let reads = 0;
  const pointed = o.pointed === true;
  const perDomain = new Map<string, number>();
  const counters = { queries: 0, blocked: 0, forwarded: 0, failed: 0, untracked: 0 };

  const windows = (): WindowsDns => ({
    v: WINDOWS_DNS_VERSION,
    adapters: (pointed ? POINTED : OWN).map((a) => ({ ...a, servers: [...a.servers] })),
  });

  const status = (): DnsStatus => ({
    v: DNS_STATUS_VERSION,
    running,
    pass_through: running && passThrough,
    binds: running ? [...BINDS] : [],
    started_at: running ? startedAt : null,
    upstreams: running ? [...upstreams] : [],
    counters: { ...counters },
    last_error: null,
    list: running
      ? { url: MOCK_LIST_URL, fetched_at: startedAt, rules: 51_234, allow: 812, skipped: 97, user_rules: false, error: null }
      : { url: null, fetched_at: null, rules: 0, allow: 0, skipped: 0, user_rules: false, error: null },
    top_blocked: [...perDomain.entries()]
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain))
      .slice(0, 20),
  });

  /** One poll's worth of lookups: they arrive only while an adapter asks the filter; nothing is blocked while passing through. */
  const traffic = () => {
    reads += 1;
    const lookups = pointed ? 6 + Math.floor(hash01(o.seed, reads, 1) * 10) : 0;
    for (let i = 0; i < lookups; i++) {
      counters.queries += 1;
      if (!passThrough && hash01(o.seed, reads, i, 2) < 0.18) {
        const r = hash01(o.seed, reads, i, 3);
        const domain = DOMAINS[Math.floor(r * r * DOMAINS.length)];
        counters.blocked += 1;
        perDomain.set(domain, (perDomain.get(domain) ?? 0) + 1);
      } else {
        counters.forwarded += 1;
      }
    }
  };

  return {
    kind: "mock",
    async start(config) {
      if (scenario === "error") throw new Error(MOCK_PORT_BUSY);
      if (running) throw new Error("DNS filter is already running; stop it first");
      running = true;
      passThrough = false;
      startedAt = now();
      upstreams = config.upstreams.map(socketAddr);
      reads = 0;
      perDomain.clear();
      Object.assign(counters, { queries: 0, blocked: 0, forwarded: 0, failed: 0, untracked: 0 });
      return status();
    },
    async stop() {
      running = false;
      startedAt = null;
      return status();
    },
    async status() {
      if (running) traffic();
      return status();
    },
    async selfCheck(): Promise<SelfCheck> {
      if (!running) throw new Error("DNS filter is not running");
      // As in Rust: the canary is answered by the filter and never counted;
      // the normal name is a real forwarded lookup on each listen address.
      counters.queries += BINDS.length;
      counters.forwarded += BINDS.length;
      return {
        pass: true,
        checks: BINDS.flatMap((server) => [
          { kind: "canary" as const, server, name: MOCK_CANARY, expect: "NOERROR 0.0.0.0 (blocked)", got: "NOERROR 0.0.0.0", pass: true },
          { kind: "resolve" as const, server, name: "example.com", expect: "NOERROR with a real address", got: "NOERROR 192.0.2.10", pass: true },
        ]),
      };
    },
    async setPassThrough(on) {
      if (!running) throw new Error("DNS filter is not running");
      passThrough = on;
      return status();
    },
    async windowsDns() {
      return windows();
    },
    async adguardRunning() {
      return o.adguard === true;
    },
  };
}
