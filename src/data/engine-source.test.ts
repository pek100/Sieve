import { describe, expect, it } from "vitest";
import { createMockEngine, MOCK_LOG_ERROR } from "./engine-mock";
import certFixture from "./fixtures/engine-ipc-v3.json";
import fixture from "./fixtures/engine-probe-v3.json";
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

  it("asks for the list report and validates it", async () => {
    const calls: string[] = [];
    const answer = { lists: [{ id: "adguard-dns", enabled: true, network: 3 }], compile_ms: 7 };
    const invoke = async <T,>(cmd: string): Promise<T> => {
      calls.push(cmd);
      return answer as T;
    };
    const source = createTauriEngine(invoke);
    expect((await source.lists()).lists[0]).toMatchObject({ id: "adguard-dns", network: 3, skipped: 0, skipped_exceptions: [], last_error: null });
    expect((await source.listsRefresh()).compile_ms).toBe(7);
    expect(calls).toEqual(["engine_lists", "engine_lists_refresh"]);
  });

  it("reads and sends the DNS resolvers, and validates what comes back", async () => {
    const calls: unknown[][] = [];
    const held = { revision: 2, upstreams: ["tls://a.example"] };
    const invoke = async <T,>(...args: unknown[]): Promise<T> => {
      calls.push(args);
      return held as T;
    };
    const source = createTauriEngine(invoke);
    expect(await source.dnsUpstreams()).toEqual(held);
    expect(await source.setDnsUpstreams(held)).toEqual(held);
    expect(calls).toEqual([["engine_dns_upstreams"], ["engine_set_dns_upstreams", { list: held }]]);
    const broken = createTauriEngine(async <T,>() => ({ revision: "x", upstreams: [] }) as T);
    await expect(broken.dnsUpstreams()).rejects.toThrow(ProtocolError);
  });

  it("asks for an update with no argument at all, and validates the Status", async () => {
    const calls: unknown[][] = [];
    const status = (fixture.examples.update_available.pipe as { status: unknown }).status;
    const invoke = async <T,>(...args: unknown[]): Promise<T> => {
      calls.push(args);
      return status as T;
    };
    const got = await createTauriEngine(invoke).requestUpdate();
    expect(got.update).toEqual({ kind: "available", version: "0.2.0" });
    expect(calls).toEqual([["engine_request_update"]]);
    await expect(createTauriEngine(async <T,>() => ({}) as T).requestUpdate()).rejects.toThrow(ProtocolError);
  });

  it("the Wi-Fi sign-in pause names only the network, the resume nothing, and both validate the Status", async () => {
    const calls: unknown[][] = [];
    const status = (fixture.examples.update_available.pipe as { status: unknown }).status;
    const invoke = async <T,>(...args: unknown[]): Promise<T> => {
      calls.push(args);
      return status as T;
    };
    const source = createTauriEngine(invoke);
    await source.pauseDnsCapture("{n}");
    await source.resumeDnsCapture();
    expect(calls).toEqual([["engine_pause_dns_capture", { network: "{n}" }], ["engine_resume_dns_capture"]]);
    await expect(createTauriEngine(async <T,>() => ({}) as T).pauseDnsCapture("{n}")).rejects.toThrow(ProtocolError);
  });

  it("a malformed answer and a failed command reject, never become a fake state", async () => {
    const bad = async <T,>(): Promise<T> => ({ v: 3, service: "running", pipe: { kind: "welcome" } }) as T;
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

  it("asks for the certificate and validates the answer; a bad one rejects", async () => {
    const calls: string[] = [];
    const answer = certFixture.certStatuses.installed;
    const invoke = async <T,>(cmd: string): Promise<T> => {
      calls.push(cmd);
      return answer as T;
    };
    const engine = createTauriEngine(invoke);
    expect(await engine.certStatus()).toEqual(answer);
    expect(await engine.installRoot()).toEqual(answer);
    expect(calls).toEqual(["engine_cert_status", "engine_install_root"]);
    const page = { revision: 1, rows: [], total: 0, next: null, scope: "browsers", browsers: [] };
    const asked: [string, unknown][] = [];
    const rows = createTauriEngine((async (cmd: string, args: unknown) => {
      asked.push([cmd, args]);
      return cmd === "engine_heal_notices" ? { run: 9, revision: 3, exclusions_revision: 4, notices: [] } : page;
    }) as never);
    expect(await rows.exclusions(5)).toEqual({ ...page, skipped: 0 });
    expect(await rows.tryDecryptAgain('"a.example"', "x.exe", "auto:pinning")).toEqual({ ...page, skipped: 0 });
    expect((await rows.healNotices(2)).exclusions_revision).toBe(4);
    expect(asked).toEqual([
      ["engine_exclusions", { after: 5 }],
      ["engine_try_decrypt_again", { line: '"a.example"', app: "x.exe", reason: "auto:pinning" }],
      ["engine_heal_notices", { after: 2 }],
    ]);
    const bad = async <T,>(): Promise<T> => ({ state: "installed" }) as T;
    await expect(createTauriEngine(bad).certStatus()).rejects.toThrow(ProtocolError);
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
