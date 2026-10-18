import { describe, expect, it } from "vitest";
import type { DnsStatus, WindowsDns } from "@/data/protocol";
import { blockRate, checkDetails, checkFailedLine, checkFailure, dnsPhase, EMPTY_DNS, isFiltering, isUpstream, strandedAdapters } from "./dns";
import { createPassedChecks } from "./checks";

const windows = (...adapters: [string, string[]][]): WindowsDns => ({
  v: 1,
  adapters: adapters.map(([alias, servers], index) => ({ alias, index, servers })),
});
const listening = (binds: string[], extra: Partial<DnsStatus> = {}): DnsStatus => ({ running: true, pass_through: false, binds, ...extra }) as DnsStatus;
const stopped = { running: false, binds: [] } as unknown as DnsStatus;

describe("upstream addresses (what dns_start accepts)", () => {
  it("takes IPv4 and IPv6, with or without a port", () => {
    for (const ok of ["1.1.1.1", "9.9.9.9:53", "2620:fe::fe", "::1", "[2606:4700::1111]:5353", "[2620:fe::fe]", "::ffff:192.0.2.1", " 1.1.1.1 "]) {
      expect(isUpstream(ok), ok).toBe(true);
    }
  });

  it("refuses names, bad numbers and broken forms", () => {
    for (const bad of ["dns.google", "", "1.1.1", "256.1.1.1", "1.1.1.1:0", "1.1.1.1:70000", "2620:fe::fe:53:1::2", "[1.1.1.1]:53", "1:2:3:4:5:6:7:8:9", "https://1.1.1.1"]) {
      expect(isUpstream(bad), bad).toBe(false);
    }
  });
});

describe("dns derivations", () => {
  it("phase follows the action in flight, then the status, then the error", () => {
    expect(dnsPhase(EMPTY_DNS)).toBe("off");
    expect(dnsPhase({ ...EMPTY_DNS, busy: "start" })).toBe("starting");
    expect(dnsPhase({ ...EMPTY_DNS, busy: "check" })).toBe("checking");
    expect(dnsPhase({ ...EMPTY_DNS, error: "port busy" })).toBe("error");
    const running = { ...EMPTY_DNS, status: { running: true } as never };
    expect(dnsPhase(running)).toBe("running");
    expect(isFiltering(running)).toBe(true);
    expect(isFiltering(EMPTY_DNS)).toBe(false);
  });

  it("block rate is absent before the first lookup, never a made-up 0", () => {
    expect(blockRate({ queries: 0, blocked: 0, forwarded: 0, failed: 0, untracked: 0 })).toBeNull();
    expect(blockRate({ queries: 200, blocked: 30, forwarded: 170, failed: 0, untracked: 0 })).toBe(0.15);
  });


  const V4 = "127.0.0.1:53";
  const V6 = "[::1]:53";
  const canary = (server: string, got: string, pass = false) =>
    ({ kind: "canary", server, name: "selfcheck.sieve.invalid", expect: "NOERROR 0.0.0.0 (blocked)", got, pass }) as const;
  const resolve = (server: string, got: string, pass = false) =>
    ({ kind: "resolve", server, name: "example.com", expect: "NOERROR with a real address", got, pass }) as const;

  it("a failed check is said once per reason, with the listeners named, and no technical reply", () => {
    // The shape of the bug the user hit: the same failure on both listeners.
    const bad = "no answer: bad name -tototix.gif: Malformed label: -tototix";
    const both = { pass: false, checks: [canary(V4, bad), resolve(V4, "NOERROR 192.0.2.1", true), canary(V6, bad), resolve(V6, "NOERROR 192.0.2.1", true)] };
    expect(checkFailure(both)).toBe(`on ${V4} and ${V6} (the test name got no answer)`);
    expect(checkFailedLine(both)).toBe(`The self check failed on ${V4} and ${V6} (the test name got no answer).`);
    expect(checkFailedLine(both)).not.toMatch(/Malformed|NOERROR|tototix/);
    const one = { pass: false, checks: [canary(V4, "no answer: timed out"), canary(V6, "NOERROR 0.0.0.0", true)] };
    expect(checkFailure(one)).toBe(`on ${V4} (the test name got no answer)`);
    const mixed = {
      pass: false,
      checks: [
        { kind: "rules", server: "", name: "", expect: "at least one block rule", got: "no block rule is loaded", pass: false } as const,
        canary(V4, "NOERROR 192.0.2.7"),
        resolve(V4, "SERVFAIL (no records)"),
        resolve(V6, "no answer: timed out"),
      ],
    };
    expect(checkFailure(mixed)).toBe(
      `(no filter list is loaded); on ${V4} (the test name was not blocked); on ${V4} (a normal name did not resolve); on ${V6} (a normal name got no answer)`,
    );
    const call = { pass: false, checks: [{ kind: "call", server: "", name: "", expect: "an answer from the filter", got: "DNS filter is not running", pass: false } as const] };
    expect(checkFailure(call)).toBe("(the check could not run)");
    expect(checkFailure({ pass: false, checks: [] })).toBe("(no check ran)");
  });

  it("details keep every technical reply with its listener, identical lines once", () => {
    const bad = "no answer: bad name -tototix.gif: Malformed label: -tototix";
    const c = { pass: false, checks: [canary(V4, bad), canary(V6, bad), canary(V4, bad), resolve(V4, "NOERROR 192.0.2.1", true)] };
    expect(checkDetails(c)).toEqual([
      `${V4}: selfcheck.sieve.invalid expected NOERROR 0.0.0.0 (blocked), got ${bad}`,
      `${V6}: selfcheck.sieve.invalid expected NOERROR 0.0.0.0 (blocked), got ${bad}`,
    ]);
    expect(checkDetails({ pass: true, checks: [resolve(V4, "NOERROR 192.0.2.1", true)] })).toEqual([]);
  });
});

describe("safety net: strandedAdapters (read only, Sieve never changes Windows DNS)", () => {
  const own = windows(["Wi-Fi", ["192.0.2.53", "2001:db8::53"]], ["Ethernet 2", ["198.51.100.53"]]);
  const pointed = windows(["Wi-Fi", ["127.0.0.1", "::1"]], ["Ethernet 2", ["198.51.100.53"]]);

  it("an adapter asking 127.0.0.1 or ::1 with no Sieve listener is stranded", () => {
    expect(strandedAdapters(pointed, null)).toEqual(["Wi-Fi"]);
    expect(strandedAdapters(pointed, stopped)).toEqual(["Wi-Fi"]);
    // Either family alone is enough: that family's lookups go nowhere.
    expect(strandedAdapters(windows(["Wi-Fi", ["192.0.2.53", "::1"]]), stopped)).toEqual(["Wi-Fi"]);
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.1"]]), stopped)).toEqual(["Wi-Fi"]);
    // Every stranded adapter, in Windows' order.
    expect(strandedAdapters(windows(["B", ["::1"]], ["A", ["192.0.2.1"]], ["C", ["127.0.0.1"]]), stopped)).toEqual(["B", "C"]);
  });

  it("Windows' own DNS is never stranded, running or not", () => {
    expect(strandedAdapters(own, stopped)).toEqual([]);
    expect(strandedAdapters(own, listening(["127.0.0.1:53", "[::1]:53"]))).toEqual([]);
    expect(strandedAdapters(windows(), stopped)).toEqual([]);
    // Other loopback addresses are not what Sieve listens on, so not Sieve's to warn about.
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.53"]]), stopped)).toEqual([]);
  });

  it("a running listener on the address answers it, pass-through included", () => {
    expect(strandedAdapters(pointed, listening(["127.0.0.1:53", "[::1]:53"]))).toEqual([]);
    expect(strandedAdapters(pointed, listening(["127.0.0.1:53", "[::1]:53"], { pass_through: true }))).toEqual([]);
    // Listening on one family only: the other family's lookups still go nowhere.
    expect(strandedAdapters(pointed, listening(["127.0.0.1:53"]))).toEqual(["Wi-Fi"]);
    expect(strandedAdapters(windows(["Wi-Fi", ["127.0.0.1"]]), listening(["127.0.0.1:53"]))).toEqual([]);
    // A test port is not where Windows asks.
    expect(strandedAdapters(pointed, listening(["127.0.0.1:5353", "[::1]:5353"]))).toEqual(["Wi-Fi"]);
    // Binds of a status that says stopped do not answer anything.
    expect(strandedAdapters(pointed, { ...listening(["127.0.0.1:53", "[::1]:53"]), running: false })).toEqual(["Wi-Fi"]);
  });

  it("unknown Windows DNS decides nothing (absent is not 'nothing pointed')", () => {
    expect(strandedAdapters(null, stopped)).toEqual([]);
    expect(strandedAdapters(null, null)).toEqual([]);
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
