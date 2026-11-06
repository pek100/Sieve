"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef } from "react";
import { exclusionsHref, noticeText, runningApp } from "@/core/exclusions";
import { newest, type SieveState } from "@/core/store";
import { useRuntime } from "./sieve-provider";
import { followExclusionsLink } from "./use-exclusions-link";
import { useEngine, useSieve } from "./use-sieve";

const SETTINGS_PATH = "/settings/";
const selectNewest = (s: SieveState) => newest(s);

/**
 * One toast per group of self-healing exclusions (plan 4.3, task D5). A new group
 * pushes one; a group that grew replaces its toast while that is still showing,
 * and after it went says nothing: the row is there, and the user was told about
 * this app in this window. A try again the client refuses is a new group, so the
 * engine's answer to asking again always reaches the user. Mounted once, in `AppShell`.
 */
export function useHealNotices() {
  const { notices } = useRuntime();
  const router = useRouter();
  const groups = useEngine().healNotices;
  const snapshot = useSieve(selectNewest);
  const told = useRef(new Map<string, { rev: number; notice: number }>());

  useEffect(() => {
    for (const group of groups ?? []) {
      const before = told.current.get(group.key);
      if (before?.rev === group.rev) continue;
      if (before && !notices.list().some((n) => n.id === before.notice)) {
        told.current.set(group.key, { ...before, rev: group.rev });
        continue;
      }
      if (before) notices.dismiss(before.notice);
      const href = exclusionsHref(group.exe, "pinning");
      const name = runningApp(snapshot, group.exe)?.name ?? group.exe;
      const notice = notices.push({
        kind: "info",
        text: noticeText(name, group),
        // Where the user is when they click: a toast outlives the page it was pushed on.
        action: { label: "Show", run: () => (window.location.pathname === SETTINGS_PATH ? followExclusionsLink(href) : router.push(href)) },
      });
      told.current.set(group.key, { rev: group.rev, notice });
    }
  }, [groups, notices, router, snapshot]);
}
