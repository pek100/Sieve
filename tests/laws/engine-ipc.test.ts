/**
 * Law 9, engine IPC: the app and the engine speak one pipe protocol, owned by
 * the Rust crate `engine/crates/sieve-ipc`. Its fixture
 * `src/data/fixtures/engine-ipc-v2.json` is read by the Rust tests
 * (`cargo test -p sieve-ipc`: every message round trips) and here: the
 * version, the limits and every message type name agree with the crate.
 * Changing a message shape bumps PROTOCOL and the fixture in one commit.
 */
import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-ipc-v2.json";
import { BLOCKER_KINDS, parseEngineStatus } from "@/data/protocol";
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
    expect(fixture.flowsBatchMs).toBe(Number(rustConst("FLOWS_BATCH_MS")));
    expect(fixture.flowsPerFrame).toBe(Number(rustConst("FLOWS_PER_FRAME")));
  });

  it("the app reads the engine's v2 status and every blocker kind the crate declares", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    expect(parseEngineStatus(body)).toEqual(body);
    const crate = (RUST.match(/pub enum Blocker \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}(\w+)\b/gm) ?? [];
    const snake = crate.map((v) => v.trim().replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()));
    expect(snake).toEqual([...BLOCKER_KINDS]);
    expect(fixture.blockers.map((b) => b.kind)).toEqual([...BLOCKER_KINDS]);
    for (const b of fixture.blockers) expect(parseEngineStatus({ ...body, blocker: b }).blocker).toEqual(b);
  });

  it("fixture names every message type of the crate, in order", () => {
    expect(fixture.client.map((m) => m.type)).toEqual(rustNames("CLIENT_TYPES"));
    expect(fixture.engine.map((m) => m.type)).toEqual(rustNames("ENGINE_TYPES"));
  });

  it("a VM row's key is the crate's vm_key, and a flow is a process's or a guest's, never both", () => {
    const body = RUST.match(/pub fn vm_key\(vm: Option<&str>\) -> String \{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(body).toContain('format!("vm:{}"');
    expect(body).toContain("to_lowercase");
    expect(rustConst("VM_UNIDENTIFIED")).toBe('"unidentified"');
    const status = fixture.engine.find((m) => m.type === "status")! as unknown as { guests: { key: string; vm: string | null }[] };
    expect(status.guests.length).toBeGreaterThan(1);
    for (const g of status.guests) expect(g.key).toBe(`vm:${(g.vm ?? "unidentified").toLowerCase()}`);
    const flows = fixture.engine.find((m) => m.type === "flows")! as unknown as { flows: { pid: number | null; forwarded: unknown }[] };
    for (const f of flows.flows) expect(f.pid === null || f.forwarded === null).toBe(true);
  });

  it("no message can sign, export or mint", () => {
    for (const name of [...rustNames("CLIENT_TYPES"), ...rustNames("ENGINE_TYPES")]) {
      expect(name).not.toMatch(/sign|export|mint|key/);
    }
  });
});
