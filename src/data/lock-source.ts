/**
 * The settings password seam. Verification lives in Rust (src-tauri/src/lock.rs)
 * and the hash never comes back over it: these answers are a state and a yes or no.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseLockStatus, parseLockVerdict, type LockStatus, type LockVerdict } from "./protocol";

export interface LockSource {
  readonly kind: "mock" | "tauri";
  status(): Promise<LockStatus>;
  verify(password: string): Promise<LockVerdict>;
  /** Set or change. Rejects with a sentence for the person. */
  set(current: string | null, next: string): Promise<void>;
  /** Remove. Rejects with a sentence for the person. */
  clear(current: string): Promise<void>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriLock(invoke: Invoke = tauriInvoke): LockSource {
  return {
    kind: "tauri",
    status: async () => parseLockStatus(await invoke<unknown>("lock_status")),
    verify: async (password) => parseLockVerdict(await invoke<unknown>("lock_verify", { password })),
    set: async (current, next) => void (await invoke<unknown>("lock_set", { current, next })),
    clear: async (current) => void (await invoke<unknown>("lock_clear", { current })),
  };
}
