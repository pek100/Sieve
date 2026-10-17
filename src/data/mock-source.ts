/**
 * Mock source: a deterministic, plausible Windows machine for the browser,
 * for tests and for e2e. Same seed and scenario give the same sequence of
 * snapshots. Flows start, persist and end (through time_wait) so charts move
 * smoothly. Addresses come from the documentation ranges only
 * (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
 *
 * Query string: ?source=mock&seed=<n>&scenario=steady|busy|empty|error
 */
import { appIdentity } from "@/core/apps";
import { GRAINS, grainMs, type HistoryQuery } from "@/core/history";
import type { Flow, History, ProcessInfo, Snapshot } from "./protocol";
import { PROTOCOL_VERSION } from "./protocol";
import { hash01, mulberry32 } from "./prng";
import type { SieveSource } from "./source";

export const MOCK_SCENARIOS = ["steady", "busy", "empty", "error"] as const;
export type MockScenario = (typeof MOCK_SCENARIOS)[number];

interface MockApp {
  product: string | null;
  exe: string | null;
  /** Display name when exe is null. */
  name?: string;
  procs: number;
  /** Mean new connections per tick at the activity peak. */
  rate: number;
  /** Connection lifetime range in ticks. */
  life: [number, number];
  listen?: number[];
  udp?: number[];
  /** Fixed pid (System is always 4). */
  pid?: number;
}

const U = "C:\\Users\\<user>";
const WIN_PRODUCT = "Microsoft Windows Operating System";

/** About 18 apps a Windows machine typically runs. Paths are scrubbed. */
export const MOCK_APPS: readonly MockApp[] = [
  { product: "Google Chrome", exe: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", procs: 4, rate: 0.9, life: [6, 60] },
  { product: "Firefox", exe: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", procs: 3, rate: 0.45, life: [6, 50] },
  { product: "Microsoft Edge", exe: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", procs: 2, rate: 0.25, life: [5, 40] },
  { product: "Visual Studio Code", exe: `${U}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe`, procs: 3, rate: 0.25, life: [10, 90], listen: [54012] },
  { product: "Discord", exe: `${U}\\AppData\\Local\\Discord\\app-1.0.9200\\Discord.exe`, procs: 2, rate: 0.2, life: [20, 120], udp: [50001] },
  { product: "Spotify", exe: `${U}\\AppData\\Roaming\\Spotify\\Spotify.exe`, procs: 2, rate: 0.22, life: [8, 70] },
  { product: "Steam", exe: "C:\\Program Files (x86)\\Steam\\steam.exe", procs: 1, rate: 0.15, life: [10, 80], listen: [27036] },
  { product: "Slack", exe: `${U}\\AppData\\Local\\slack\\app-4.41.0\\slack.exe`, procs: 2, rate: 0.15, life: [15, 100] },
  { product: "Microsoft Teams", exe: `${U}\\AppData\\Local\\Microsoft\\WindowsApps\\ms-teams.exe`, procs: 2, rate: 0.18, life: [15, 100] },
  { product: "Microsoft OneDrive", exe: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", procs: 1, rate: 0.1, life: [5, 30] },
  { product: "Microsoft Outlook", exe: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", procs: 1, rate: 0.08, life: [20, 120] },
  { product: "Zoom", exe: `${U}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe`, procs: 1, rate: 0.04, life: [30, 200], udp: [8801] },
  { product: "NVIDIA Container", exe: "C:\\Program Files\\NVIDIA Corporation\\NvContainer\\nvcontainer.exe", procs: 1, rate: 0.04, life: [5, 20] },
  { product: "Git", exe: "C:\\Program Files\\Git\\mingw64\\bin\\git-remote-https.exe", procs: 1, rate: 0.03, life: [3, 12] },
  { product: "Node.js", exe: "C:\\Program Files\\nodejs\\node.exe", procs: 1, rate: 0.05, life: [5, 40], listen: [3000] },
  { product: WIN_PRODUCT, exe: "C:\\Windows\\explorer.exe", procs: 1, rate: 0.05, life: [5, 30] },
  { product: WIN_PRODUCT, exe: "C:\\Windows\\System32\\svchost.exe", procs: 3, rate: 0.12, life: [3, 25], udp: [5353, 5355] },
  { product: WIN_PRODUCT, exe: "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe", procs: 1, rate: 0.06, life: [3, 20] },
  { product: null, exe: null, name: "System", procs: 1, rate: 0, life: [1, 1], listen: [445, 139], pid: 4 },
];

const REMOTE_V4 = ["203.0.113.", "198.51.100.", "192.0.2."];
const LOCAL_V4 = "10.0.0.20";
const LOCAL_V6 = "2001:db8::20";
const REMOTE_PORTS = [443, 443, 443, 443, 80, 5228, 3478, 8443];
const WARMUP_TICKS = 30;
const HOUR = 3_600_000;
const HISTORY_SPAN = 28 * 24 * HOUR;

interface Live {
  flow: Flow;
  /** Tick at which the flow ends (enters time_wait). */
  endsAt: number;
}

export interface MockOptions {
  seed: number;
  scenario?: MockScenario;
  /** Clock for snapshot `t`. Tests pass a fake; content never depends on it. */
  now?: () => number;
}

export function createMockSource({ seed, scenario = "steady", now = Date.now }: MockOptions): SieveSource {
  const rand = mulberry32(seed);
  const scale = scenario === "busy" ? 2.5 : scenario === "empty" ? 0 : 1;

  // Stable processes: pids derived from seed and app index.
  const processes: ProcessInfo[] = [];
  const pidsOf: number[][] = [];
  MOCK_APPS.forEach((app, i) => {
    const pids: number[] = [];
    for (let k = 0; k < app.procs; k++) {
      // Each app owns a 1024-wide pid block, so pids never collide.
      const pid = app.pid ?? 1200 + i * 1024 + Math.floor(hash01(seed, i) * 200) * 4 + k * 4;
      pids.push(pid);
      processes.push({
        pid,
        exe: app.exe,
        name: app.exe ? (app.exe.split("\\").pop() ?? app.exe) : (app.name ?? `pid ${pid}`),
        product: app.product,
      });
    }
    pidsOf.push(pids);
  });
  // One process the OS refuses to describe (elevated, access denied).
  const hiddenPid = 20000 + Math.floor(hash01(seed, 99) * 1000) * 4;
  processes.push({ pid: hiddenPid, exe: null, name: `pid ${hiddenPid}`, product: null });

  // Per-app remote host pools and activity phases.
  const hosts = MOCK_APPS.map((_, i) => {
    const n = 2 + Math.floor(hash01(seed, i, 7) * 5);
    return Array.from({ length: n }, (_, k) => {
      const v6 = hash01(seed, i, k, 3) < 0.15;
      if (v6) return { family: "v6" as const, addr: `2001:db8:${i + 1}::${k + 10}` };
      const prefix = REMOTE_V4[Math.floor(hash01(seed, i, k, 1) * REMOTE_V4.length)];
      return { family: "v4" as const, addr: `${prefix}${1 + Math.floor(hash01(seed, i, k, 2) * 250)}` };
    });
  });
  const phase = MOCK_APPS.map((_, i) => hash01(seed, i, 11) * Math.PI * 2);
  const period = MOCK_APPS.map((_, i) => 60 + Math.floor(hash01(seed, i, 13) * 240));

  // Listening sockets never change.
  const listeners: Flow[] = [];
  MOCK_APPS.forEach((app, i) => {
    for (const port of app.listen ?? []) {
      listeners.push({
        pid: pidsOf[i][0],
        proto: "tcp",
        family: "v4",
        local: { addr: app.pid === 4 ? "0.0.0.0" : "127.0.0.1", port },
        remote: null,
        state: "listen",
      });
    }
    for (const port of app.udp ?? []) {
      listeners.push({
        pid: pidsOf[i][0],
        proto: "udp",
        family: "v4",
        local: { addr: "0.0.0.0", port },
        remote: null,
        state: "none",
      });
    }
  });

  let tick = 0;
  let nextPort = 49152 + Math.floor(rand() * 4000);
  let live: Live[] = [];

  const step = () => {
    tick += 1;
    // End flows: established -> time_wait for 2 ticks -> gone.
    live = live
      .filter((l) => tick < l.endsAt + 2)
      .map((l) =>
        tick >= l.endsAt && l.flow.state === "established" ? { ...l, flow: { ...l.flow, state: "time_wait" } } : l,
      );
    // Start flows.
    MOCK_APPS.forEach((app, i) => {
      const wave = 0.6 + 0.4 * Math.sin((2 * Math.PI * tick) / period[i] + phase[i]);
      let budget = app.rate * scale * wave;
      while (budget > 0) {
        const r = rand();
        if (r >= Math.min(budget, 0.95)) break;
        budget -= 1;
        const pool = hosts[i];
        const host = pool[Math.floor(rand() * pool.length)];
        const [lo, hi] = app.life;
        nextPort = nextPort >= 65000 ? 49152 : nextPort + 1;
        live.push({
          endsAt: tick + lo + Math.floor(rand() * (hi - lo + 1)),
          flow: {
            pid: pidsOf[i][Math.floor(rand() * pidsOf[i].length)],
            proto: "tcp",
            family: host.family,
            local: { addr: host.family === "v6" ? LOCAL_V6 : LOCAL_V4, port: nextPort },
            remote: { addr: host.addr, port: REMOTE_PORTS[Math.floor(rand() * REMOTE_PORTS.length)] },
            state: "established",
          },
        });
      }
    });
  };

  for (let k = 0; k < WARMUP_TICKS; k++) step();

  return {
    kind: "mock",
    async sample(): Promise<Snapshot> {
      if (scenario === "error") throw new Error("Mock source: scenario error (no data on purpose)");
      step();
      return {
        v: PROTOCOL_VERSION,
        t: now(),
        processes: processes.map((p) => ({ ...p })),
        flows: [...listeners, ...live.map((l) => l.flow)].map((f) => ({ ...f })),
      };
    },
    async history(q: HistoryQuery): Promise<History> {
      if (scenario === "error") throw new Error("Mock source: scenario error (no data on purpose)");
      return mockHistory(q, { seed, scale, now: now() });
    },
  };
}

/** Busyness of the machine at `t`, local time: office hours busiest, nights nearly idle. */
function dayCurve(t: number): number {
  const d = new Date(t);
  const hour = d.getHours();
  const weekend = d.getDay() === 0 || d.getDay() === 6;
  const day = hour >= 9 && hour < 18 ? 1 : hour >= 18 && hour < 23 ? 0.7 : hour >= 7 ? 0.4 : 0.08;
  return (weekend ? 0.55 : 1) * day;
}

/**
 * The mock's persisted history, in the same shape and under the same rules
 * as the Rust store: the grain is kept only for its retention (GRAINS), a
 * bucket holds one sample per second, apps with no flows have no row, and
 * buckets are summed into `step`. Four weeks deep at most; `empty` has none.
 * Each app's mean active connections follow its live rate and lifetime,
 * scaled by the time of day with per-hour noise.
 */
export function mockHistory(q: HistoryQuery, o: { seed: number; scale: number; now: number }): History {
  const g = grainMs(q.grain);
  const keep = GRAINS.find((x) => x.name === q.grain)?.keepMs ?? HISTORY_SPAN;
  const out: History = { v: PROTOCOL_VERSION, grain: q.grain, step: q.step, samples: [], apps: [] };
  if (o.scale === 0 || q.step <= 0 || q.step % g !== 0) return out;
  const end = Math.min(q.to, o.now);
  const start = Math.max(q.from, end - Math.min(HISTORY_SPAN, keep));
  const ids = MOCK_APPS.map((a) => appIdentity({ pid: 0, exe: a.exe, name: a.name ?? "", product: a.product }));
  const samples = new Map<number, number>();
  const flows = new Map<string, { t: number; app: string; name: string; flows: number }>();
  for (let t = Math.ceil(start / g) * g; t < end; t += g) {
    const b = Math.floor(t / q.step) * q.step;
    const n = g / 1000;
    samples.set(b, (samples.get(b) ?? 0) + n);
    const curve = dayCurve(t);
    MOCK_APPS.forEach((app, i) => {
      const meanLife = (app.life[0] + app.life[1]) / 2;
      const noise = 0.75 + 0.5 * hash01(o.seed, i, Math.floor(t / HOUR));
      const mean = app.rate * o.scale * meanLife * curve * noise;
      const f = Math.round(mean * n);
      if (f <= 0) return;
      const id = ids[i];
      const k = `${b}|${id.key}`;
      const row = flows.get(k) ?? { t: b, app: id.key, name: id.name, flows: 0 };
      row.flows += f;
      flows.set(k, row);
    });
  }
  out.samples = [...samples.entries()].sort(([a], [b]) => a - b).map(([t, n]) => ({ t, n }));
  out.apps = [...flows.values()].sort((a, b) => a.t - b.t || a.app.localeCompare(b.app));
  return out;
}
