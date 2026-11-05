import { describe, expect, it } from "vitest";
import certFixture from "./fixtures/engine-ipc-v2.json";
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

  it("a malformed answer and a failed command reject, never become a fake state", async () => {
    const bad = async <T,>(): Promise<T> => ({ v: 2, service: "running", pipe: { kind: "welcome" } }) as T;
    await expect(createTauriEngine(bad).probe()).rejects.toThrow(ProtocolError);
    const failed = async <T,>(): Promise<T> => {
      throw new Error("service manager: Access is denied.");
    };
    await expect(createTauriEngine(failed).probe()).rejects.toThrow("Access is denied");
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
    const bad = async <T,>(): Promise<T> => ({ state: "installed" }) as T;
    await expect(createTauriEngine(bad).certStatus()).rejects.toThrow(ProtocolError);
  });
});
