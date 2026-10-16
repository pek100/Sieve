import { describe, expect, it } from "vitest";
import type { Flow, Snapshot } from "@/data/protocol";
import { createMockSource } from "@/data/mock-source";
import { deltaDir, kpis, kpiValues } from "./kpis";
import type { Level } from "./policy";

const proc = (pid: number, product: string) => ({ pid, exe: `C:\\Apps\\${product}.exe`, name: `${product}.exe`, product });
const tcp = (pid: number, remote: string | null, state: Flow["state"], port = 50000): Flow => ({
  pid,
  proto: "tcp",
  family: "v4",
  local: { addr: "10.0.0.20", port },
  remote: remote === null ? null : { addr: remote, port: 443 },
  state,
});

const snap = (flows: Flow[], t = 1): Snapshot => ({
  v: 1,
  t,
  processes: [proc(10, "Alpha"), proc(20, "Beta"), proc(30, "Gamma")],
  flows,
});

const watchAll = (): Level => "watch";

describe("kpis", () => {
  it("counts apps with active flows, connections, distinct hosts and listening ports", () => {
    const s = snap([
      tcp(10, "203.0.113.5", "established", 50001),
      tcp(10, "203.0.113.5", "time_wait", 50002),
      tcp(20, "198.51.100.7", "established", 50003),
      tcp(30, null, "listen", 3000),
      { pid: 30, proto: "udp", family: "v4", local: { addr: "0.0.0.0", port: 5353 }, remote: null, state: "none" },
    ]);
    expect(kpiValues(s, watchAll)).toEqual({ apps: 2, connections: 3, hosts: 2, ports: 2 });
  });

  it("an app at level off is not counted as sieved", () => {
    const s = snap([tcp(10, "203.0.113.5", "established"), tcp(20, "198.51.100.7", "established")]);
    const levelOf = (k: string): Level => (k === "alpha" ? "off" : "watch");
    expect(kpiValues(s, levelOf).apps).toBe(1);
  });

  it("gives each KPI a delta against the window start", () => {
    const start = snap([tcp(10, "203.0.113.5", "established")], 1);
    const end = snap([tcp(20, "198.51.100.7", "established"), tcp(20, "198.51.100.8", "established", 50009)], 2);
    const k = kpis([start, end], watchAll)!;
    expect(k.map((x) => [x.id, x.value, x.delta, x.dir])).toEqual([
      ["apps", 1, 0, "flat"],
      ["connections", 2, 1, "up"],
      ["hosts", 2, 1, "up"],
      ["ports", 0, 0, "flat"],
    ]);
    expect(kpis([], watchAll)).toBeNull();
    expect([deltaDir(-2), deltaDir(0), deltaDir(3)]).toEqual(["down", "flat", "up"]);
  });

  it("works on mock data: System listens but is never a sieved app", async () => {
    const src = createMockSource({ seed: 1, now: () => 1 });
    const v = kpiValues(await src.sample(), watchAll);
    expect(v.apps).toBeGreaterThan(5);
    expect(v.connections).toBeGreaterThan(v.apps);
    expect(v.ports).toBeGreaterThanOrEqual(5);
  });
});
