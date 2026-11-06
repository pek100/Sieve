"use client";

import { useEffect, useState } from "react";
import { WELCOME_DONE } from "@/core/welcome";
import { useRuntime } from "./sieve-provider";
import { useSetting } from "./use-sieve";

/**
 * Whether the first-run guide takes over now: only where it is offered, and only
 * once the stored settings are read, so a returning person never sees it.
 *
 * Due or not is decided once per run, from the stored flag at that moment, and
 * finishing ends it. So turning the flag off in Settings shows the guide the next
 * time Sieve opens, as the row says, and never replaces the screen under the person.
 */
export function useWelcome(): { show: boolean; done: () => void } {
  const { settings, welcomeOnFirstRun } = useRuntime();
  const [finished] = useSetting(WELCOME_DONE);
  const [due, setDue] = useState(false);
  useEffect(() => {
    let live = true;
    void settings.ready.then(() => {
      if (live) setDue(welcomeOnFirstRun && !settings.get(WELCOME_DONE));
    });
    return () => {
      live = false;
    };
  }, [settings, welcomeOnFirstRun]);
  if (due && finished) setDue(false);
  // Past the write gate on purpose (law 14): the guide replaces every screen, so
  // leaving it must never wait on a password, and this flag changes no traffic.
  return { show: due && !finished, done: () => void settings.set(WELCOME_DONE, true) };
}
