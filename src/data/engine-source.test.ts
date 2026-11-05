import { describe, expect, it } from "vitest";
import fixture from "./fixtures/engine-probe-v2.json";
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

  it("a malformed answer and a failed command reject, never become a fake state", async () => {
    const bad = async <T,>(): Promise<T> => ({ v: 3, service: "running", pipe: { kind: "welcome" } }) as T;
    await expect(createTauriEngine(bad).probe()).rejects.toThrow(ProtocolError);
    const failed = async <T,>(): Promise<T> => {
      throw new Error("service manager: Access is denied.");
    };
    await expect(createTauriEngine(failed).probe()).rejects.toThrow("Access is denied");
  });
});
