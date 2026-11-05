"use client";

import { useSyncExternalStore } from "react";
import type { LockController, LockState } from "@/data/lock-controller";
import { useRuntime } from "./sieve-provider";

/** The settings password's state and its controller (owner: the lock controller). */
export function useLock(): { state: LockState; lock: LockController } {
  const { lockController: lock } = useRuntime();
  const state = useSyncExternalStore(lock.subscribe, lock.state, lock.state);
  return { state, lock };
}
