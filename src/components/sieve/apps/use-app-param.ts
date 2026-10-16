"use client";

import { useCallback, useSyncExternalStore } from "react";

/**
 * The `?app=<key>` deep link for the detail panel. Static export has no
 * dynamic routes, so the open app lives in the query string. Read from
 * window.location (no Suspense needed) and written with history.replaceState,
 * keeping every other parameter (?source, ?seed, ?scenario) as it is.
 */
const PARAM = "app";
const CHANGED = "sieve:app-param";

function subscribe(onChange: () => void) {
  window.addEventListener("popstate", onChange);
  window.addEventListener(CHANGED, onChange);
  return () => {
    window.removeEventListener("popstate", onChange);
    window.removeEventListener(CHANGED, onChange);
  };
}

const read = () => new URLSearchParams(window.location.search).get(PARAM);
const readOnServer = () => null;

export function useAppParam(): [string | null, (key: string | null) => void] {
  const value = useSyncExternalStore(subscribe, read, readOnServer);
  const set = useCallback((key: string | null) => {
    const url = new URL(window.location.href);
    if (key === null) url.searchParams.delete(PARAM);
    else url.searchParams.set(PARAM, key);
    window.history.replaceState(null, "", url);
    window.dispatchEvent(new Event(CHANGED));
  }, []);
  return [value, set];
}
