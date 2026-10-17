/**
 * Law 3, protocol: the v1 fixture parses on the TS side (the Rust side
 * parses it in `cargo test`), and the TS and Rust definitions agree on the
 * version and on every flow state's wire name.
 */
import { describe, expect, it } from "vitest";
import { GRAINS } from "@/core/history";
import { parseTrayAction } from "@/core/tray";
import { TRAY_EVENT } from "@/data/desktop";
import historyFixture from "@/data/fixtures/history-v1.json";
import dnsFixture from "@/data/fixtures/dns-status-v3.json";
import fixture from "@/data/fixtures/snapshot-v1.json";
import systemFixture from "@/data/fixtures/system-dns-v1.json";
import { MOCK_CANARY } from "@/data/dns-mock";
import {
  CHECK_KINDS,
  DNS_STATUS_VERSION,
  FLOW_STATES,
  PROTOCOL_VERSION,
  SYSTEM_DNS_VERSION,
  parseDnsStatus,
  parseHistory,
  parseSelfCheck,
  parseSnapshot,
  parseSystemDns,
  ProtocolError,
} from "@/data/protocol";
import { read } from "./files";

const RUST = read("src-tauri/src/protocol.rs");

describe("protocol law", () => {
  it("parses the v1 fixture losslessly", () => {
    const snap = parseSnapshot(fixture);
    expect(snap).toEqual(fixture);
    expect(snap.v).toBe(PROTOCOL_VERSION);
  });

  it("matches the Rust protocol version", () => {
    const m = RUST.match(/pub const PROTOCOL_VERSION: u32 = (\d+);/);
    expect(Number(m?.[1])).toBe(PROTOCOL_VERSION);
  });

  it("matches the Rust flow state names, in order", () => {
    const m = RUST.match(/FLOW_STATE_NAMES: \[&str; \d+\] = \[([\s\S]*?)\];/);
    const names = [...(m?.[1] ?? "").matchAll(/"([a-z0-9_]+)"/g)].map((x) => x[1]);
    expect(names).toEqual([...FLOW_STATES]);
  });

  it("parses the v1 history fixture losslessly", () => {
    expect(parseHistory(historyFixture)).toEqual(historyFixture);
    expect(() => parseHistory({ ...historyFixture, v: 2 })).toThrow(ProtocolError);
    expect(() => parseHistory({ ...historyFixture, grain: "week" })).toThrow(/grain/);
    expect(() => parseHistory({ ...historyFixture, apps: [{ ...historyFixture.apps[0], flows: -1 }] })).toThrow(/apps\[0\]\.flows/);
  });

  it("history grains, widths and retention match the Rust store", () => {
    const arr = (name: string) => {
      const m = RUST.match(new RegExp(`pub const ${name}: \\[[^\\]]+\\] = \\[([^\\]]*)\\];`));
      return [...(m?.[1] ?? "").matchAll(/"([a-z]+)"|([\d_]+)/g)].map((x) => x[1] ?? Number(x[2].replace(/_/g, "")));
    };
    expect(arr("GRAIN_NAMES")).toEqual(GRAINS.map((g) => g.name));
    expect(arr("GRAIN_MS")).toEqual(GRAINS.map((g) => g.ms));
    expect(arr("GRAIN_KEEP_MS")).toEqual(GRAINS.map((g) => g.keepMs));
  });

  it("the tray speaks the same event name and actions as src-tauri/src/tray.rs", () => {
    const tray = read("src-tauri/src/tray.rs");
    expect(tray.match(/pub const TRAY_EVENT: &str = "([^"]+)";/)?.[1]).toBe(TRAY_EVENT);
    const minutes = Number(tray.match(/pub const TRAY_PAUSE_MINUTES: u32 = (\d+);/)?.[1]);
    const ids = [...(tray.match(/pub const MENU: [^=]+= \[([\s\S]*?)\];/)?.[1] ?? "").matchAll(/\("([a-z_]+)", "([^"]+)"\)/g)];
    // What Rust emits for its Pause and Resume items (serde tag "kind", snake_case) is what the window accepts.
    expect(parseTrayAction({ kind: "pause", minutes })).toEqual({ kind: "pause", minutes });
    expect(parseTrayAction({ kind: "resume" })).toEqual({ kind: "resume" });
    // Quit is sent to the window while Sieve's DNS backup exists, so the window can ask first.
    expect(parseTrayAction({ kind: "quit" })).toEqual({ kind: "quit" });
    expect(ids.map((m) => m[1])).toEqual(["pause", "resume", "open", "quit"]);
    // The Pause item's label states the same minutes it sends.
    expect(ids[0][2]).toBe(`Pause ${minutes} min`);
  });

  it("dns_status: the v3 fixture parses losslessly and the version matches Rust", () => {
    expect(parseDnsStatus(dnsFixture)).toEqual(dnsFixture);
    const rust = read("src-tauri/src/dns/status.rs");
    expect(Number(rust.match(/pub const DNS_STATUS_VERSION: u32 = (\d+);/)?.[1])).toBe(DNS_STATUS_VERSION);
    // Rust serialises against the same file.
    expect(rust).toContain('include_str!("../../../src/data/fixtures/dns-status-v3.json")');
    expect(() => parseDnsStatus({ ...dnsFixture, v: 2 })).toThrow(/version 2 is not 3.*Restart Sieve/);
    expect(() => parseDnsStatus({ ...dnsFixture, v: 2 })).toThrow(ProtocolError);
    expect(() => parseDnsStatus({ ...dnsFixture, pass_through: "no" })).toThrow(/pass_through/);
    expect(() => parseDnsStatus({ ...dnsFixture, binds: "127.0.0.1:53" })).toThrow(/binds/);
    expect(() => parseDnsStatus({ ...dnsFixture, counters: { ...dnsFixture.counters, blocked: -1 } })).toThrow(/counters\.blocked/);
    expect(() => parseDnsStatus({ ...dnsFixture, top_blocked: [{ domain: 3, count: 1 }] })).toThrow(/top_blocked\[0\]\.domain/);
  });

  it("system_dns_state: the v1 fixture parses losslessly and the version matches Rust", () => {
    expect(parseSystemDns(systemFixture)).toEqual(systemFixture);
    const rust = read("src-tauri/src/sysdns/mod.rs");
    expect(Number(rust.match(/pub const SYSTEM_DNS_VERSION: u32 = (\d+);/)?.[1])).toBe(SYSTEM_DNS_VERSION);
    expect(rust).toContain('include_str!("../../../src/data/fixtures/system-dns-v1.json")');
    expect(() => parseSystemDns({ ...systemFixture, v: 2 })).toThrow(ProtocolError);
    expect(() => parseSystemDns({ ...systemFixture, interfaces: [{ ...systemFixture.interfaces[0], v4: null }] })).toThrow(/interfaces\[0\]\.v4/);
  });

  it("dns_self_check: the Rust Check fields are the ones parsed", () => {
    const probe = read("src-tauri/src/dns/probe.rs");
    const fields = [...(probe.match(/pub struct Check \{([\s\S]*?)\}/)?.[1] ?? "").matchAll(/pub (\w+):/g)].map((m) => m[1]);
    const check = { kind: "canary", server: "127.0.0.1:53", name: "selfcheck.sieve.invalid", expect: "x", got: "y", pass: true };
    expect(fields).toEqual(Object.keys(check));
    expect(parseSelfCheck({ pass: true, checks: [check] })).toEqual({ pass: true, checks: [check] });
    expect(() => parseSelfCheck({ pass: "yes", checks: [] })).toThrow(/pass/);
    expect(() => parseSelfCheck({ pass: true, checks: [{ ...check, kind: "call" }] })).toThrow(/checks\[0\]\.kind/);
    expect(() => parseSelfCheck({ pass: true, checks: [{ ...check, kind: undefined }] })).toThrow(/checks\[0\]\.kind/);
  });

  it("dns_self_check: the Rust CheckKind variants are CHECK_KINDS, and the canary name agrees", () => {
    const probe = read("src-tauri/src/dns/probe.rs");
    const body = probe.match(/pub enum CheckKind \{([\s\S]*?)\}/)?.[1] ?? "";
    const variants = [...body.matchAll(/^\s*(\w+),/gm)].map((m) => m[1].toLowerCase());
    expect(variants).toEqual([...CHECK_KINDS]);
    expect(probe).toContain('#[serde(rename_all = "lowercase")]');
    const rules = read("src-tauri/src/dns/rules.rs");
    expect(rules.match(/pub const CANARY_NAME: &str = "([^"]+)";/)?.[1]).toBe(MOCK_CANARY);
  });

  it("rejects a snapshot from another version or with a broken flow", () => {
    expect(() => parseSnapshot({ ...fixture, v: 2 })).toThrow(ProtocolError);
    const broken = { ...fixture, flows: [{ ...fixture.flows[0], state: "listening" }] };
    expect(() => parseSnapshot(broken)).toThrow(/flows\[0\]\.state/);
    const badPort = { ...fixture, flows: [{ ...fixture.flows[0], local: { addr: "x", port: 70000 } }] };
    expect(() => parseSnapshot(badPort)).toThrow(/port/);
  });
});
