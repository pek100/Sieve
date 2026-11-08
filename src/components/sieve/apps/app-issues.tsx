"use client";

import { AlertTriangle, ClipboardCopy, EyeOff, Power, RotateCcw, ShieldCheck, Lock, type LucideIcon } from "lucide-react";
import { useExclusionRows } from "@/components/sieve/settings/use-exclusions";
import { RulePreview } from "@/components/sieve/log/rule-preview";
import { useRowActions } from "@/components/sieve/log/use-log";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Button } from "@/components/ui/button";
import { iconExe } from "@/core/apps";
import type { AppEntry } from "@/core/apps-actions";
import { engineRoutes, engineVersion } from "@/core/engine";

import {
  appFixes,
  CAUSE_TEXT,
  factTime,
  failingOpen,
  FIX_TEXT,
  issueName,
  fixPreview,
  problemFixes,
  problemText,
  reportText,
  retriesText,
  summaryText,
  troubled,
  UNTOUCHED_TEXT,
  verdict,
  VERDICT_TEXT,
  type Fix,
} from "@/core/issues";
import type { AppIssues, Problem } from "@/data/protocol";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useEngineActions } from "@/hooks/use-sieve";
import { Monogram } from "./monogram";

const FIX_ICON: Record<Fix, LucideIcon> = {
  unblock: ShieldCheck,
  stop_decrypting: EyeOff,
  keep_untouched: Lock,
  try_again: RotateCcw,
  turn_off: Power,
  report: ClipboardCopy,
};

const NO_APPS: AppIssues[] = [];

/** The engine's apps with problems, or none while it is not routing. */
function useIssues() {
  const e = useEngine();
  const routes = engineRoutes(e);
  return { routes, apps: routes ? (e.issues?.apps ?? NO_APPS) : NO_APPS, error: routes ? (e.issuesError ?? null) : null };
}

/**
 * "Having trouble", above the app groups: each app whose connections failed in the
 * last hour, how many, and whether Sieve is the likely cause, in words. A row opens
 * the app's sheet, where the problems and their fixes are. Nothing while no app
 * has trouble; a failed read says so and keeps what was read.
 */
export function TroubleList({ apps, known, open }: { apps: readonly AppEntry[]; known: readonly { key: string; name: string }[]; open: (key: string) => void }) {
  const { apps: issues, error } = useIssues();
  const rows = troubled(issues);
  if (rows.length === 0 && error === null) return null;
  return (
    <section aria-labelledby="apps-trouble-title" data-testid="trouble" className="flex flex-col">
      <h3 id="apps-trouble-title" className="flex h-9 items-center gap-2 text-label text-on-surface-muted">
        <AlertTriangle className="size-4 text-warning" strokeWidth={1.75} aria-hidden="true" />
        Having trouble
      </h3>
      {error !== null && (
        <p className="text-label text-on-surface-muted" data-testid="trouble-error">
          Sieve could not read the apps&apos; problems just now: {error}
        </p>
      )}
      <ul className="flex flex-col gap-1">
        {rows.map((a) => {
          const entry = apps.find((x) => x.key === a.key);
          const name = issueName(a, known);
          return (
            <li key={a.key} data-testid="trouble-row" data-app={a.key} data-verdict={verdict(a)}>
              <button type="button" onClick={() => open(a.key)} className="relative flex min-h-14 w-full items-center gap-3 overflow-hidden rounded-sm py-2 pr-2 text-left">
                <AppIcon exe={entry ? iconExe(entry) : null}>
                  <Monogram appKey={a.key} name={name} />
                </AppIcon>
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate text-body-strong text-on-surface">{name}</span>
                  <span className="text-caption text-on-surface-muted">
                    {summaryText(a)}. {VERDICT_TEXT[verdict(a)]}
                  </span>
                </span>
                <StateLayer />
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function ProblemRow({ problem, exe, onFix }: { problem: Problem; exe: string | null; onFix: (fix: Fix, p: Problem) => void }) {
  const when = factTime(problem.last_ms);
  return (
    <li data-testid="problem" data-signal={problem.signal} data-cause={problem.cause} className="flex flex-col gap-1 py-1">
      <span className="text-body break-words text-on-surface">{problemText(problem)}</span>
      <span className="text-caption text-on-surface-muted">
        {CAUSE_TEXT[problem.cause] ?? CAUSE_TEXT.unknown}
        {when ? `, last at ${when}` : ""}
      </span>
      {problemFixes(problem, exe).map((fix) => {
        const Icon = FIX_ICON[fix];
        return (
          <span key={fix} className="pt-1">
            <Button variant="secondary" onClick={() => onFix(fix, problem)} aria-label={`${FIX_TEXT[fix]}: ${problem.host}`}>
              <Icon strokeWidth={1.75} />
              {FIX_TEXT[fix]}
            </Button>
          </span>
        );
      })}
    </li>
  );
}

/**
 * The app sheet's "Problems" section: the likely cause first, with the app's
 * one-step fixes under it, then each problem with when and how often, and the
 * fix of that one problem where Sieve did it. What
 * is written is shown before it is written (`RulePreview`); Off is the switch's
 * own write. Nothing leaves the PC: the report goes to the clipboard.
 */
export function AppProblems({ appKey, name, canTurnOff, turnOff }: { appKey: string; name: string; canTurnOff: boolean; turnOff: () => void }) {
  const { routes, apps, error } = useIssues();
  const e = useEngine();
  const rows = useExclusionRows();
  const { notices } = useRuntime();
  const { tryDecryptAgain } = useEngineActions();
  const preview = useRowActions();
  if (!routes) return null;
  const issues = apps.find((a) => a.key === appKey) ?? null;
  const exe = issues?.exe ?? null;
  const untouched = failingOpen(rows, exe);

  const copyReport = (a: AppIssues) => {
    void (async () => navigator.clipboard.writeText(reportText(a, name, engineVersion(e))))().then(
      () => notices.push({ kind: "success", text: "Report copied. Paste it wherever you ask for help; Sieve sends nothing." }),
      () => notices.push({ kind: "error", text: "Could not copy the report." }),
    );
  };
  const fix = (f: Fix, p: Problem | null) => {
    if (f === "turn_off") return turnOff();
    if (f === "report") return issues && copyReport(issues);
    if (f === "try_again") return void (exe && tryDecryptAgain("*", exe, "auto:failing"));
    const line = fixPreview(f, p?.host ?? null, exe);
    if (line) preview.ask(line);
  };

  return (
    <section className="flex flex-col gap-2" data-testid="app-problems">
      <h3 className="text-label text-on-surface-muted">Problems in the last hour</h3>
      {error !== null && <p className="text-label text-on-surface-muted">Sieve could not read this app&apos;s problems just now: {error}</p>}
      {issues === null ? (
        <p className="text-body text-on-surface-faint">No problems Sieve saw.</p>
      ) : (
        <>
          <p className="text-body text-on-surface" data-testid="app-verdict">
            {VERDICT_TEXT[verdict(issues)]} {summaryText(issues)}.
          </p>
          {retriesText(issues) && <p className="text-label text-on-surface-muted">{retriesText(issues)}</p>}
          {untouched && (
            <p className="text-label text-on-surface-muted" data-testid="app-untouched">
              {factTime(untouched.createdMs) ? `Since ${factTime(untouched.createdMs)}, ` : ""}{UNTOUCHED_TEXT}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            {appFixes(issues, untouched, canTurnOff).map((f) => {
              const Icon = FIX_ICON[f];
              return (
                <Button key={f} variant="secondary" onClick={() => fix(f, null)}>
                  <Icon strokeWidth={1.75} />
                  {FIX_TEXT[f]}
                </Button>
              );
            })}
          </div>
          <ul className="flex flex-col gap-2">
            {issues.problems.map((p) => (
              <ProblemRow key={`${p.signal}|${p.host ?? ""}`} problem={p} exe={exe} onFix={fix} />
            ))}
          </ul>
        </>
      )}
      <RulePreview preview={preview.preview} onConfirm={() => void preview.confirm()} onCancel={preview.cancelPreview} />
    </section>
  );
}
