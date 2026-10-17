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
import fixture from "@/data/fixtures/snapshot-v1.json";
import { FLOW_STATES, PROTOCOL_VERSION, parseHistory, parseSnapshot, ProtocolError } from "@/data/protocol";
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
    expect(ids.map((m) => m[1])).toEqual(["pause", "resume", "open", "quit"]);
    // The Pause item's label states the same minutes it sends.
    expect(ids[0][2]).toBe(`Pause ${minutes} min`);
  });

  it("rejects a snapshot from another version or with a broken flow", () => {
    expect(() => parseSnapshot({ ...fixture, v: 2 })).toThrow(ProtocolError);
    const broken = { ...fixture, flows: [{ ...fixture.flows[0], state: "listening" }] };
    expect(() => parseSnapshot(broken)).toThrow(/flows\[0\]\.state/);
    const badPort = { ...fixture, flows: [{ ...fixture.flows[0], local: { addr: "x", port: 70000 } }] };
    expect(() => parseSnapshot(badPort)).toThrow(/port/);
  });
});
