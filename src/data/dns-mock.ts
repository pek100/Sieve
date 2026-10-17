/**
 * Mock DNS source: a deterministic DNS filter and Windows DNS for the
 * browser, tests and e2e. Counters grow with every status read while the
 * filter runs (content depends on the read count and seed, never on the
 * clock). Addresses come from the documentation ranges only.
 *
 * Query string: ?dns=off|running|error (default off), ?adguard=1.
 * - off: nothing runs, Windows uses its own DNS; starting works.
 * - running: Windows already points at Sieve and Sieve's backup exists, as
 *   after a restart while pointed; the window must start the filter itself.
 * - error: starting fails because port 53 is taken.
 */
import { DNS_STATUS_VERSION, SYSTEM_DNS_VERSION, type DnsStatus, type InterfaceDns, type SelfCheck, type SystemDnsState } from "./protocol";
import { hash01 } from "./prng";
import type { DnsSource } from "./dns-source";

export const DNS_SCENARIOS = ["off", "running", "error"] as const;
export type DnsScenario = (typeof DNS_SCENARIOS)[number];

export interface MockDnsOptions {
  seed: number;
  scenario?: DnsScenario;
  adguard?: boolean;
  /** Clock for started_at and fetched_at; content never depends on it. */
  now?: () => number;
}

export const MOCK_LIST_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
export const MOCK_PORT_BUSY =
  "cannot listen on 127.0.0.1:53: Only one usage of each socket address (protocol/network address/port) is normally permitted. (os error 10048)";
const BINDS = ["127.0.0.1:53", "[::1]:53"];
const MOCK_BACKUP_DIR = "C:\\Users\\<user>\\AppData\\Roaming\\app.sieve.desktop\\system-dns";

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

const own = (alias: string, index: number, v4: string[], v6: string[], dhcp: boolean): InterfaceDns => ({
  alias,
  index,
  v4: { servers: v4, dhcp },
  v6: { servers: v6, dhcp },
  uses_sieve: false,
});

/** What Windows had before Sieve: one adapter on DHCP, one set by hand. */
const ORIGINAL: readonly InterfaceDns[] = [
  own("Wi-Fi", 12, ["192.0.2.53"], ["2001:db8::53"], true),
  own("Ethernet 2", 7, ["198.51.100.53", "203.0.113.53"], [], false),
];

const pointedAt = (it: InterfaceDns): InterfaceDns => ({
  ...it,
  v4: { servers: ["127.0.0.1"], dhcp: false },
  v6: { servers: ["::1"], dhcp: false },
  uses_sieve: true,
});

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
  let startedAt: number | null = null;
  let upstreams: string[] = [];
  let reads = 0;
  let pointed = scenario === "running";
  let backup = scenario === "running";
  const perDomain = new Map<string, number>();
  const counters = { queries: 0, blocked: 0, forwarded: 0, failed: 0, untracked: 0 };

  const system = (): SystemDnsState => ({
    v: SYSTEM_DNS_VERSION,
    interfaces: ORIGINAL.map((it) => (pointed ? pointedAt(it) : it)),
    pointed,
    backup,
    backup_dir: backup ? MOCK_BACKUP_DIR : null,
  });

  const status = (): DnsStatus => ({
    v: DNS_STATUS_VERSION,
    running,
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

  /** One poll's worth of lookups: only while Windows uses the filter does anything get blocked. */
  const traffic = () => {
    reads += 1;
    const lookups = pointed ? 6 + Math.floor(hash01(o.seed, reads, 1) * 10) : 0;
    for (let i = 0; i < lookups; i++) {
      counters.queries += 1;
      if (hash01(o.seed, reads, i, 2) < 0.18) {
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
      // The probe queries count, as in Rust: one blocked per listen address, one forwarded.
      counters.queries += BINDS.length + 1;
      counters.blocked += BINDS.length;
      counters.forwarded += 1;
      perDomain.set(DOMAINS[0], (perDomain.get(DOMAINS[0]) ?? 0) + BINDS.length);
      return {
        pass: true,
        checks: [
          ...BINDS.map((server) => ({ server, name: DOMAINS[0], expect: "NOERROR 0.0.0.0 (blocked)", got: "NOERROR 0.0.0.0", pass: true })),
          { server: BINDS[0], name: "example.com", expect: "NOERROR with a real address", got: "NOERROR 192.0.2.10", pass: true },
        ],
      };
    },
    async systemState() {
      return system();
    },
    async pointSystem() {
      if (!running) throw new Error("Start DNS filtering before pointing Windows at it");
      if (backup) throw new Error("A backup from an earlier change exists; restore it first");
      backup = true;
      pointed = true;
      return system();
    },
    async restoreSystem() {
      if (!backup) throw new Error("There is no backup to restore");
      backup = false;
      pointed = false;
      return system();
    },
    async adguardRunning() {
      return o.adguard === true;
    },
  };
}
