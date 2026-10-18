/**
 * Law 9, engine IPC: the app and the engine speak one pipe protocol, owned by
 * the Rust crate `engine/crates/sieve-ipc`. Its fixture
 * `src/data/fixtures/engine-ipc-v1.json` is read by the Rust tests
 * (`cargo test -p sieve-ipc`: every message round trips) and here: the
 * version, the limits and every message type name agree with the crate.
 * Changing a message shape bumps PROTOCOL and the fixture in one commit.
 */
import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-ipc-v1.json";
import { read } from "./files";

const RUST = read("engine/crates/sieve-ipc/src/lib.rs");

function rustConst(name: string): string {
  const m = RUST.match(new RegExp(`pub const ${name}: [^=]+= ([^;]+);`));
  if (!m) throw new Error(`${name} not found in sieve-ipc`);
  return m[1];
}

function rustNames(name: string): string[] {
  return [...rustConst(name).matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
}

describe("engine IPC law", () => {
  it("fixture version and limits match the crate", () => {
    expect(fixture.protocol).toBe(Number(rustConst("PROTOCOL")));
    expect(fixture.supported).toEqual(JSON.parse(rustConst("SUPPORTED")));
    expect(fixture.maxFrame).toBe(1 << Number(rustConst("MAX_FRAME").replace("1 << ", "")));
    expect(fixture.pipe).toBe(rustConst("PIPE_NAME").replace(/^r"|"$/g, ""));
  });

  it("fixture names every message type of the crate, in order", () => {
    expect(fixture.client.map((m) => m.type)).toEqual(rustNames("CLIENT_TYPES"));
    expect(fixture.engine.map((m) => m.type)).toEqual(rustNames("ENGINE_TYPES"));
  });

  it("no message can sign, export or mint", () => {
    for (const name of [...rustNames("CLIENT_TYPES"), ...rustNames("ENGINE_TYPES")]) {
      expect(name).not.toMatch(/sign|export|mint|key/);
    }
  });
});
