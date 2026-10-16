"use client";

import { useEffect, useSyncExternalStore } from "react";
import { useSetting } from "./use-sieve";

export type ResolvedTheme = "dark" | "light";

const QUERY = "(prefers-color-scheme: light)";

function subscribeSystem(cb: () => void) {
  if (typeof window === "undefined" || !window.matchMedia) return () => {};
  const mq = window.matchMedia(QUERY);
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
}

function systemTheme(): ResolvedTheme {
  if (typeof window === "undefined" || !window.matchMedia) return "dark";
  return window.matchMedia(QUERY).matches ? "light" : "dark";
}

/** The theme actually shown: the appearance.theme setting with "system" resolved. */
export function useResolvedTheme(): ResolvedTheme {
  const [choice] = useSetting("appearance.theme");
  const system = useSyncExternalStore(subscribeSystem, systemTheme, () => "dark" as const);
  return choice === "system" ? system : choice;
}

/** Writes the resolved theme to <html data-theme>, which tokens.css keys on. */
export function useThemeSync(): void {
  const theme = useResolvedTheme();
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
}
