"use client";

import { useEffect, useState } from "react";
import { SearchField } from "@/components/sieve/primitives/search-field";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { fetchWords } from "@/core/custom-lists";
import type { ListRules } from "@/data/protocol";

/** The list whose rules are shown. */
export interface RulesTarget {
  id: string;
  title: string;
}

/** How long typing pauses before the engine is asked: one question per pause, not per key. */
const SEARCH_PAUSE_MS = 250;

/** What is on show, with the search it answers: a caption never pairs one search with another's answer. */
type Shown = { kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; rules: ListRules; query: string };

const count = (n: number) => n.toLocaleString("en-US");

/** What the lines shown are, of how many. Absent is never zero: nothing is said until the engine answered. */
export function rulesCaption(rules: ListRules, query: string): string {
  const of = query.trim() === "" ? `${count(rules.total)} rules` : `${count(rules.matched)} of ${count(rules.total)} rules match`;
  if (rules.matched === 0) return query.trim() === "" ? "This list holds no rules." : `No rule holds "${query.trim()}".`;
  return rules.lines.length < rules.matched ? `${of}. The first ${count(rules.lines.length)} are shown; search to find others.` : `${of}.`;
}

/** The body: mounted only while open, so each opening starts from an empty search. */
function RulesBody({ target, load }: { target: RulesTarget; load: (id: string, query: string) => Promise<ListRules> }) {
  const [query, setQuery] = useState("");
  const [shown, setShown] = useState<Shown>({ kind: "loading" });
  useEffect(() => {
    let live = true;
    const ask = () =>
      load(target.id, query).then(
        (rules) => live && setShown({ kind: "ready", rules, query }),
        (e: unknown) => live && setShown({ kind: "error", message: e instanceof Error ? e.message : String(e) }),
      );
    const t = setTimeout(ask, query === "" ? 0 : SEARCH_PAUSE_MS);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [load, target.id, query]);
  return (
    <div className="flex min-h-0 flex-col gap-3">
      <SearchField value={query} onChange={setQuery} label={`Search the rules of ${target.title}`} placeholder="Search rules" />
      {shown.kind === "loading" && <p className="text-label text-on-surface-muted">Reading the list</p>}
      {shown.kind === "error" && (
        <p role="alert" className="text-label text-on-surface-muted" data-rules-error="">
          {/* The engine's own words beside what they mean. */}
          {/no copy/i.test(shown.message) ? "Sieve has no copy of this list yet. It downloads a list while the list is on and the engine routes traffic." : fetchWords(shown.message)}{" "}
          <span className="font-mono text-mono">{shown.message}</span>
        </p>
      )}
      {shown.kind === "ready" && (
        <>
          <p className="text-label text-on-surface-muted tabular" aria-live="polite" data-rules-caption="" data-for={shown.query}>
            {shown.query === query ? rulesCaption(shown.rules, shown.query) : "Searching"}
          </p>
          {shown.rules.lines.length > 0 && (
            <ul aria-label={`Rules of ${target.title}`} className="flex max-h-[50dvh] flex-col gap-1 overflow-y-auto rounded-sm bg-inset p-3 shadow-inset" data-rules-lines="">
              {shown.rules.lines.map((line, i) => (
                <li key={`${i}:${line}`} className="font-mono text-mono break-all text-on-surface">
                  {line}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

/** A list's rules, read only: searchable, and as many as the engine sends at once. */
export function RulesDialog({ target, load, onClose }: { target: RulesTarget | null; load: (id: string, query: string) => Promise<ListRules>; onClose: () => void }) {
  return (
    <Dialog open={target !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto bg-surface-3 text-on-surface sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-title">{target ? `Rules in ${target.title}` : "Rules"}</DialogTitle>
          <DialogDescription className="text-body text-on-surface-muted">{"Read only. These come from the copy Sieve's engine holds."}</DialogDescription>
        </DialogHeader>
        {target && <RulesBody target={target} load={load} />}
      </DialogContent>
    </Dialog>
  );
}
