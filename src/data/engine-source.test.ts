import { describe, expect, it } from "vitest";
import { createMockEngine, MOCK_LOG_ERROR } from "./engine-mock";
import fixture from "./fixtures/engine-probe-v2.json";
import logFixture from "./fixtures/engine-log-v1.json";
import { createTauriEngine } from "./engine-source";
import { ProtocolError } from "./protocol";

describe("Tauri engine source", () => {
  it("asks engine_probe and validates the answer", async () => {
    const calls: string[] = [];
    const invoke = async <T,>(cmd: string): Promise<T> => {
      calls.push(cmd);
      return fixture.examples.idle as T;
    };
    expect(await createTauriEngine(invoke).probe()).toEqual(fixture.examples.idle);
    expect(calls).toEqual(["engine_probe"]);
  });

  it("a malformed answer and a failed command reject, never become a fake state", async () => {
    const bad = async <T,>(): Promise<T> => ({ v: 2, service: "running", pipe: { kind: "welcome" } }) as T;
    await expect(createTauriEngine(bad).probe()).rejects.toThrow(ProtocolError);
    const failed = async <T,>(): Promise<T> => {
      throw new Error("service manager: Access is denied.");
    };
    await expect(createTauriEngine(failed).probe()).rejects.toThrow("Access is denied");
  });

  it("asks engine_log_tail with the cursor and validates the answer", async () => {
    const calls: [string, unknown][] = [];
    const invoke = async <T,>(cmd: string, args?: unknown): Promise<T> => {
      calls.push([cmd, args]);
      return logFixture as T;
    };
    const tail = await createTauriEngine(invoke).logTail(4);
    expect(calls).toEqual([["engine_log_tail", { since: 4 }]]);
    expect(tail.rows).toHaveLength(logFixture.rows.length);
    const bad = async <T,>(): Promise<T> => ({ v: 9, rows: [] }) as T;
    await expect(createTauriEngine(bad).logTail(0)).rejects.toThrow(ProtocolError);
  });
});

describe("mock engine log", () => {
  it("answers only where the engine routes", async () => {
    for (const s of ["missing", "idle", "adguard"] as const) {
      expect((await createMockEngine(s).logTail(0)).rows, s).toEqual([]);
    }
    expect((await createMockEngine("filtering").logTail(0)).rows.length).toBeGreaterThan(0);
  });

  it("every fixture row on the first read, then one host-level row per read, from the seed and read count", async () => {
    const read = async (seed: number) => {
      const m = createMockEngine("hosts", { seed });
      const first = await m.logTail(0);
      const second = await m.logTail(first.next);
      const third = await m.logTail(second.next);
      return { first, second, third };
    };
    const a = await read(1);
    expect(a.first.rows).toHaveLength(logFixture.rows.length);
    expect(a.first.next).toBe(logFixture.rows.length);
    expect(a.second.rows).toHaveLength(1);
    expect(a.second.rows[0].row.url).toBeNull();
    expect(a.third.rows[0].seq).toBe(a.second.rows[0].seq + 1);
    expect(await read(1)).toEqual(a);
  });

  it("uses documentation ranges and example hosts only", () => {
    for (const { row } of logFixture.rows) {
      expect(row.host).toMatch(/\.example(\.(com|net|org))?$|^198\.51\.100\.|^203\.0\.113\.|^192\.0\.2\./);
      expect(row.remote).toMatch(/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|\[2001:db8:)/);
    }
  });

  it("?log=error fails every read with the same message", async () => {
    await expect(createMockEngine("hosts", { logError: true }).logTail(0)).rejects.toThrow(MOCK_LOG_ERROR);
  });
});
