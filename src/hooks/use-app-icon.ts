"use client";

import { useEffect, useMemo, useState } from "react";
import { iconExes } from "@/core/apps";
import { newest, type SieveState } from "@/core/store";
import type { AppIcon } from "@/data/protocol";
import type { SieveSource } from "@/data/source";
import { useRuntime } from "./sieve-provider";
import { useSieve } from "./use-sieve";

/**
 * One request per exe per source for the life of the window (the Rust side
 * caches on disk as well). A failed request is "no icon": an icon is
 * decoration, so it never becomes an error on screen.
 */
const requests = new WeakMap<SieveSource, Map<string, Promise<AppIcon | null>>>();

function request(source: SieveSource, exe: string): Promise<AppIcon | null> {
  let bySource = requests.get(source);
  if (!bySource) {
    bySource = new Map();
    requests.set(source, bySource);
  }
  let p = bySource.get(exe);
  if (!p) {
    p = source.appIcon(exe).catch(() => null);
    bySource.set(exe, p);
  }
  return p;
}

/**
 * The icon of `exe`: undefined while it loads, null when there is none,
 * else the icon. It is asked for when the component that shows it mounts.
 */
export function useAppIcon(exe: string | null): AppIcon | null | undefined {
  const { source } = useRuntime();
  // The answer is pinned to the exe it is for: a new exe shows loading, never the old icon.
  const [answer, setAnswer] = useState<{ exe: string; icon: AppIcon | null } | null>(null);
  useEffect(() => {
    if (exe === null) return;
    let alive = true;
    void request(source, exe).then((icon) => alive && setAnswer({ exe, icon }));
    return () => {
      alive = false;
    };
  }, [source, exe]);
  if (exe === null) return null;
  return answer?.exe === exe ? answer.icon : undefined;
}

const selectNewest = (s: SieveState) => newest(s);

/** Each app's icon exe in the newest snapshot, by app key. */
export function useIconExes(): ReadonlyMap<string, string> {
  const snap = useSieve(selectNewest);
  return useMemo(() => (snap ? iconExes(snap) : new Map<string, string>()), [snap]);
}
