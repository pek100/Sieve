"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";
import { groupApps } from "@/core/apps";
import { startedFailing, startedFailingText } from "@/core/issues";
import { newest, type SieveState } from "@/core/store";
import { useRuntime } from "./sieve-provider";
import { useEngine, useSieve } from "./use-sieve";

const selectNewest = (s: SieveState) => newest(s);

/** Where "Show" goes: the app's sheet, where its problems and fixes are. */
export const appHref = (key: string) => `/apps/?app=${encodeURIComponent(key)}`;

/**
 * One gentle notice per app that starts failing repeatedly right after Sieve
 * began filtering it (`startedFailing`), once per engine run. It asks for a
 * desktop notification too, which `bindNotifications` sends only while the
 * user's notification setting is on (off by default) and the window is not in
 * front. What the engine held when this window first read it is not news: the
 * Apps screen shows it. Mounted once, in `AppShell`.
 */
export function useIssueNotices() {
  const { notices } = useRuntime();
  const router = useRouter();
  const issues = useEngine().issues ?? null;
  const snapshot = useSieve(selectNewest);
  const told = useRef<Set<string> | null>(null);

  useEffect(() => {
    if (issues === null) return;
    const failing = issues.apps.filter(startedFailing).map((a) => ({ app: a, id: `${issues.run}:${a.key}` }));
    if (told.current === null) {
      told.current = new Set(failing.map((f) => f.id));
      return;
    }
    for (const { app, id } of failing) {
      if (told.current.has(id)) continue;
      told.current.add(id);
      const name = (snapshot ? groupApps(snapshot) : []).find((a) => a.key === app.key)?.name ?? app.exe ?? app.key;
      notices.push({ kind: "info", desktop: true, text: startedFailingText(name), action: { label: "Show", run: () => router.push(appHref(app.key)) } });
    }
  }, [issues, notices, router, snapshot]);
}
