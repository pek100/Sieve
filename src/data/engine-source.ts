/**
 * The engine seam: every question the window asks about the filtering
 * engine, and every request it makes, goes through one EngineSource. `tauri`
 * calls the Rust commands (src-tauri/src/engine.rs, adguard.rs) and validates
 * the answers; `mock` (engine-mock.ts) answers from the fixture's examples
 * for the browser, tests and e2e. A Tauri error is passed through as is,
 * never replaced by mock data.
 *
 * The app never installs, starts or stops the engine. It sends the user's
 * switch (`setPolicy`), and, only when the user clicks, stops or starts
 * AdGuard's service through one command Windows asks the user to approve.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseCertStatus, parseEngineProbe, parseEngineStatus, type CertStatus, type EnginePolicy, type EngineProbe, type EngineStatus } from "./protocol";

export interface EngineSource {
  readonly kind: "mock" | "tauri";
  /** The engine's facts now. Rejects only when they cannot be read at all. */
  probe(): Promise<EngineProbe>;
  /** Sends the user's switches; resolves with the engine's Status after the change. */
  setPolicy(policy: EnginePolicy): Promise<EngineStatus>;
  /** Stops AdGuard's service (Windows asks the user first). Rejects when it did not stop. */
  stopAdguard(): Promise<void>;
  /** Starts AdGuard's service again (Windows asks the user first). */
  startAdguard(): Promise<void>;
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
    stopAdguard: async () => void (await invoke<unknown>("adguard_stop")),
    startAdguard: async () => void (await invoke<unknown>("adguard_start")),
    certStatus: async () => parseCertStatus(await invoke<unknown>("engine_cert_status")),
    installRoot: async () => parseCertStatus(await invoke<unknown>("engine_install_root")),
  };
}
