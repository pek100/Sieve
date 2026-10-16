/**
 * Law 3, protocol: the v1 fixture parses on the TS side (the Rust side
 * parses it in `cargo test`), and the TS and Rust definitions agree on the
 * version and on every flow state's wire name.
 */
import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/snapshot-v1.json";
import { FLOW_STATES, PROTOCOL_VERSION, parseSnapshot, ProtocolError } from "@/data/protocol";
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

  it("rejects a snapshot from another version or with a broken flow", () => {
    expect(() => parseSnapshot({ ...fixture, v: 2 })).toThrow(ProtocolError);
    const broken = { ...fixture, flows: [{ ...fixture.flows[0], state: "listening" }] };
    expect(() => parseSnapshot(broken)).toThrow(/flows\[0\]\.state/);
    const badPort = { ...fixture, flows: [{ ...fixture.flows[0], local: { addr: "x", port: 70000 } }] };
    expect(() => parseSnapshot(badPort)).toThrow(/port/);
  });
});
