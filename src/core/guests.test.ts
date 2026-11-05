import { describe, expect, it } from "vitest";
import { matchesQuery } from "./apps-actions";
import { attribution, hostAttribution, type EngineSlice } from "./engine";
import { VM_UNIDENTIFIED_LABEL, guestRows } from "./guests";
import type { EngineCounters, EngineStatus } from "@/data/protocol";

const named = { key: "vm:devbox", vm: "DevBox", seen: 4, open: 1 };
const unidentified = { key: "vm:unidentified", vm: null, seen: 2, open: 0 };

describe("guestRows", () => {
  it("names a VM by what the engine said", () => {
    expect(guestRows([named])).toEqual([{ key: "vm:devbox", name: "DevBox", exes: [], open: 1 }]);
  });

  it("labels the row with no name", () => {
    expect(guestRows([unidentified])).toEqual([{ key: "vm:unidentified", name: VM_UNIDENTIFIED_LABEL, exes: [], open: 0 }]);
    expect(VM_UNIDENTIFIED_LABEL).toBe("Unidentified virtual machine traffic");
  });

  it("keeps the engine's order: named rows, then the unidentified one", () => {
    expect(guestRows([named, unidentified]).map((r) => r.key)).toEqual(["vm:devbox", "vm:unidentified"]);
  });

  it("no status or no guests is no rows", () => {
    expect(guestRows(undefined)).toEqual([]);
    expect(guestRows(null)).toEqual([]);
    expect(guestRows([])).toEqual([]);
  });

  it("search reads a row like an app", () => {
    const [row] = guestRows([named]);
    expect(matchesQuery(row, "devb")).toBe(true);
    expect(matchesQuery(row, "chrome")).toBe(false);
    expect(matchesQuery(row, "  ")).toBe(true);
  });
});

function slice(counters: Partial<EngineCounters> | null): EngineSlice {
  const full: EngineCounters = {
    flows: 0,
    attributed: 0,
    own_refused: 0,
    dns_answers: 0,
    packets_in: 0,
    packets_out: 0,
    not_unicast: 0,
    forwarded: 0,
    forwarded_named: 0,
    etw_found: 0,
    etw_disagreed: 0,
    etw_dropped: 0,
    ...counters,
  };
  const status = { counters: full } as EngineStatus;
  const pipe = counters === null ? null : { kind: "welcome", engine_version: "0.1.0", session_id: 1, status };
  return { probe: { v: 2, service: "running", adguard: "missing", pipe } } as unknown as EngineSlice;
}

describe("the two attribution rates", () => {
  it("100 flows, 90 host, 5 named, 5 unnamed: the gate is 0.95 and host only is 1.0", () => {
    const e = slice({ flows: 100, attributed: 95, forwarded: 10, forwarded_named: 5 });
    expect(attribution(e)).toBe(0.95);
    expect(hostAttribution(e)).toBe(1);
  });

  it("host only is null at 0 flows, with no status, and when every flow was forwarded", () => {
    expect(hostAttribution(slice({}))).toBeNull();
    expect(hostAttribution(slice(null))).toBeNull();
    const all = slice({ flows: 10, attributed: 6, forwarded: 10, forwarded_named: 6 });
    expect(hostAttribution(all)).toBeNull();
    expect(attribution(all)).toBe(0.6);
  });
});
