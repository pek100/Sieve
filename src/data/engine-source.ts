/**
 * The engine seam: every question the window asks about the filtering
 * engine, and every request it makes, goes through one EngineSource. `tauri`
 * calls the Rust commands (src-tauri/src/engine.rs, adguard.rs) and validates
 * the answers; `mock` (engine-mock.ts) answers from the fixture's examples
 * for the browser, tests and e2e. A Tauri error is passed through as is,
 * never replaced by mock data.
 *
 * The app never installs, starts or stops the engine. It sends the user's
 * switches (`setPolicy`), reads the per-list report (`lists`), asks the engine to update
 * (`requestUpdate`, the engine alone fetches and verifies), and, only when the user clicks, stops or starts
 * AdGuard's service through one command Windows asks the user to approve.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseCertStatus, parseEngineLists, parseEngineProbe, parseEngineStatus, parseLogTail, type CertStatus, type EngineLists, type EnginePolicy, type EngineProbe, type EngineStatus, type LogTail } from "./protocol";

export interface EngineSource {
  readonly kind: "mock" | "tauri";
  /** The engine's facts now. Rejects only when they cannot be read at all. */
  probe(): Promise<EngineProbe>;
  /** Sends the user's switches; resolves with the engine's Status after the change. */
  setPolicy(policy: EnginePolicy): Promise<EngineStatus>;
  /** The per-list report. */
  lists(): Promise<EngineLists>;
  /** Asks the engine to download every selected list now; the report as it stands. */
  listsRefresh(): Promise<EngineLists>;
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
  /** Log rows after `since` from the tail the app keeps in memory. Rejects when it cannot be read. */
  logTail(since: number): Promise<LogTail>;
  /** The root certificate's facts. Rejects when the engine did not answer. */
  certStatus(): Promise<CertStatus>;
  /** The user's Reinstall: a new root and key. Rejects while `https` is off in the engine. */
  installRoot(): Promise<CertStatus>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriEngine(invoke: Invoke = tauriInvoke): EngineSource {
  return {
    kind: "tauri",
    probe: async () => parseEngineProbe(await invoke<unknown>("engine_probe")),
    setPolicy: async (policy) => parseEngineStatus(await invoke<unknown>("engine_set_policy", { policy })),
    lists: async () => parseEngineLists(await invoke<unknown>("engine_lists")),
    listsRefresh: async () => parseEngineLists(await invoke<unknown>("engine_lists_refresh")),
    requestUpdate: async () => parseEngineStatus(await invoke<unknown>("engine_request_update")),
    stopAdguard: async () => void (await invoke<unknown>("adguard_stop")),
    startAdguard: async () => void (await invoke<unknown>("adguard_start")),
    logTail: async (since) => parseLogTail(await invoke<unknown>("engine_log_tail", { since })),
    certStatus: async () => parseCertStatus(await invoke<unknown>("engine_cert_status")),
    installRoot: async () => parseCertStatus(await invoke<unknown>("engine_install_root")),
  };
}
