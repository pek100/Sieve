import { describe, expect, it } from "vitest";
import type { WindowsDns } from "@/data/protocol";
import { strandedAdapters } from "./dns";
import { createPassedChecks } from "./checks";

const windows = (...adapters: [string, string[]][]): WindowsDns => ({
  v: 1,
  adapters: adapters.map(([alias, servers], index) => ({ alias, index, servers })),
});

describe("safety net: strandedAdapters (read only, Sieve never changes Windows DNS)", () => {
  it("an adapter asking 127.0.0.1 or ::1 is stranded", () => {
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.1", "::1"]], ["Ethernet 2", ["198.51.100.53"]]))).toEqual(["Wi-Fi"]);
    // Either family alone is enough: that family's lookups go nowhere.
    expect(strandedAdapters(windows(["Wi-Fi", ["192.0.2.53", "::1"]]))).toEqual(["Wi-Fi"]);
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.1"]]))).toEqual(["Wi-Fi"]);
    // Every stranded adapter, in Windows' order, each once.
    expect(strandedAdapters(windows(["B", ["::1"]], ["A", ["192.0.2.1"]], ["C", ["127.0.0.1"]], ["B", ["127.0.0.1"]]))).toEqual(["B", "C"]);
  });

  it("Windows' own DNS is never stranded", () => {
    expect(strandedAdapters(windows(["Wi-Fi", ["192.0.2.53", "2001:db8::53"]], ["Ethernet 2", ["198.51.100.53"]]))).toEqual([]);
    expect(strandedAdapters(windows())).toEqual([]);
    // Other loopback addresses are not what an old Sieve build pointed at.
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.53"]]))).toEqual([]);
  });

  it("unknown Windows DNS decides nothing (absent is not 'nothing pointed')", () => {
    expect(strandedAdapters(null)).toEqual([]);
  });
});

describe("passed checks", () => {
  it("notifies on change only and bumps its version", () => {
    const c = createPassedChecks();
    let n = 0;
    c.subscribe(() => (n += 1));
    c.add("a");
    c.add("a");
    expect([c.has("a"), n, c.version()]).toEqual([true, 1, 1]);
    c.delete("b");
    c.delete("a");
    expect([c.has("a"), n]).toEqual([false, 2]);
  });
});
