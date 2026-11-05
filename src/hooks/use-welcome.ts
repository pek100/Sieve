"use client";

import { useEffect, useState } from "react";
import { WELCOME_DONE } from "@/core/welcome";
import { useRuntime } from "./sieve-provider";
import { useSetting } from "./use-sieve";

/**
 * Whether the first-run guide takes over now: only where it is offered, and only
 * once the stored settings are read, so a returning person never sees it.
 */
export function useWelcome(): { show: boolean; done: () => void } {
  const { settings, welcomeOnFirstRun } = useRuntime();
  const [finished] = useSetting(WELCOME_DONE);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let live = true;
    void settings.ready.then(() => {
      if (live) setLoaded(true);
    });
    return () => {
      live = false;
    };
  }, [settings]);
  // Past the write gate on purpose (law 14): the guide replaces every screen, so
  // leaving it must never wait on a password, and this flag changes no traffic.
  return { show: welcomeOnFirstRun && loaded && !finished, done: () => void settings.set(WELCOME_DONE, true) };
}
