/**
 * The engine seam: every question the window asks about the filtering
 * engine goes through one EngineSource. `tauri` calls the read-only Rust
 * command `engine_probe` (src-tauri/src/engine.rs) and validates the answer;
 * `mock` (engine-mock.ts) answers from the fixture's examples for the
 * browser, tests and e2e. A Tauri error is passed through as is, never
 * replaced by mock data. The app never installs, starts or stops the engine.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseEngineProbe, type EngineProbe } from "./protocol";

export interface EngineSource {
  readonly kind: "mock" | "tauri";
  /** The engine's facts now. Rejects only when they cannot be read at all. */
  probe(): Promise<EngineProbe>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriEngine(invoke: Invoke = tauriInvoke): EngineSource {
  return {
    kind: "tauri",
    probe: async () => parseEngineProbe(await invoke<unknown>("engine_probe")),
  };
}
