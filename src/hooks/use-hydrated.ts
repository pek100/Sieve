"use client";

import { useSyncExternalStore } from "react";

const noop = () => () => {};

/** false during the static prerender and the hydration pass, true after. */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    noop,
    () => true,
    () => false,
  );
}
