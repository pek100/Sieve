"use client";

import { useCallback, useMemo, useSyncExternalStore } from "react";
import { APP_PARAM, EXCLUSIONS_ANCHOR, REASON_PARAM, exclusionsLink, type ReasonGroup } from "@/core/exclusions";

/**
 * The "Not decrypted" view's filter, in the query string so a link can open it:
 * read from window.location (no Suspense needed) and written with
 * history.replaceState, keeping every other parameter, as `useAppParam` does.
 */
const CHANGED = "sieve:exclusions-link";

function subscribe(onChange: () => void) {
  window.addEventListener("popstate", onChange);
  window.addEventListener(CHANGED, onChange);
  return () => {
    window.removeEventListener("popstate", onChange);
    window.removeEventListener(CHANGED, onChange);
  };
}

const read = () => window.location.search;
const readOnServer = () => "";

function write(change: (q: URLSearchParams) => void) {
  const url = new URL(window.location.href);
  change(url.searchParams);
  window.history.replaceState(null, "", url);
  window.dispatchEvent(new Event(CHANGED));
}

/** Follows a link to the view from the page the view is on: a push would change nothing the view can see. */
export function followExclusionsLink(href: string) {
  const asked = new URL(href, window.location.href).searchParams;
  write((q) => {
    for (const name of [APP_PARAM, REASON_PARAM]) {
      const value = asked.get(name);
      if (value === null) q.delete(name);
      else q.set(name, value);
    }
  });
  document.getElementById(EXCLUSIONS_ANCHOR)?.scrollIntoView?.();
}

export function useExclusionsLink(): { app: string | null; group: ReasonGroup; setGroup: (g: ReasonGroup) => void; clearApp: () => void } {
  const search = useSyncExternalStore(subscribe, read, readOnServer);
  const link = useMemo(() => exclusionsLink(search), [search]);
  const setGroup = useCallback((g: ReasonGroup) => write((q) => (g === "all" ? q.delete(REASON_PARAM) : q.set(REASON_PARAM, g))), []);
  const clearApp = useCallback(() => write((q) => q.delete(APP_PARAM)), []);
  return { ...link, setGroup, clearApp };
}
