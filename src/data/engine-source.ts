/**
 * The engine seam: every question the window asks about the filtering
 * engine, and every request it makes, goes through one EngineSource. `tauri`
 * calls the Rust commands (src-tauri/src/engine.rs, adguard.rs) and validates
 * the answers; `mock` (engine-mock.ts) answers from the fixture's examples
 * for the browser, tests and e2e. A Tauri error is passed through as is,
 * never replaced by mock data.
 *
 * The app never installs, starts or stops the engine. It sends the user's
 * switch (`setPolicy`), asks the engine to update (`requestUpdate`, the engine
 * alone fetches and verifies), and, only when the user clicks, stops or starts
 * AdGuard's service through one command Windows asks the user to approve.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseEngineProbe, parseEngineStatus, type EnginePolicy, type EngineProbe, type EngineStatus } from "./protocol";

export interface EngineSource {
  readonly kind: "mock" | "tauri";
  /** The engine's facts now. Rejects only when they cannot be read at all. */
  probe(): Promise<EngineProbe>;
  /** Sends the user's switches; resolves with the engine's Status after the change. */
  setPolicy(policy: EnginePolicy): Promise<EngineStatus>;
  /**
   * `RequestUpdate`: no argument, ever. The engine decides from its own state
   * whether this checks or applies the release it offers, and verifies
   * everything itself. Rejects when it refused (asked again too soon).
   */
  requestUpdate(): Promise<EngineStatus>;
  /** Stops AdGuard's service (Windows asks the user first). Rejects when it did not stop. */
  stopAdguard(): Promise<void>;
  /** Starts AdGuard's service again (Windows asks the user first). */
  startAdguard(): Promise<void>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriEngine(invoke: Invoke = tauriInvoke): EngineSource {
  return {
    kind: "tauri",
    probe: async () => parseEngineProbe(await invoke<unknown>("engine_probe")),
    setPolicy: async (policy) => parseEngineStatus(await invoke<unknown>("engine_set_policy", { policy })),
    requestUpdate: async () => parseEngineStatus(await invoke<unknown>("engine_request_update")),
    stopAdguard: async () => void (await invoke<unknown>("adguard_stop")),
    startAdguard: async () => void (await invoke<unknown>("adguard_start")),
  };
}
