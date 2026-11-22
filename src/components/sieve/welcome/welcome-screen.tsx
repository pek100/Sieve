"use client";

import Link from "next/link";
import { useState } from "react";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { LockNote } from "@/components/sieve/settings/setting-row";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { PENDING_SWITCH_CLASS, useSettingsView, valueInForce, waitsForEngine } from "@/components/sieve/settings/use-settings-view";
import { ADGUARD_PAUSE_TEXT, HTTPS_HREF, HTTPS_INVITE, HTTPS_SWITCH, engineInForce } from "@/core/engine";
import type { Section } from "@/core/settings/registry";
import { dataSwitchSummary, switchesState, welcomeAdguard, welcomeSteps } from "@/core/welcome";
import { useEngine, useEngineActions } from "@/hooks/use-sieve";

const NO_BLOCKS: ReadonlySet<Section> = new Set();

/**
 * The first-run guide. It explains, and changes the network only on the person's
 * click: its switches are Settings' own (the settings view's `set`, so the
 * password gate, `requires` and the engine's locks hold as on the Settings row,
 * and a locked one shows why), each at its value in force; the other action is
 * the existing pause offer. No step writes a switch by itself. Skip is always one
 * click (plan D14).
 */
export function WelcomeScreen({ onDone }: { onDone: () => void }) {
  const engine = useEngine();
  const { stopAdguard } = useEngineActions();
  const { doc, lockOf, set } = useSettingsView("", NO_BLOCKS);
  const [at, setAt] = useState(0);
  const [offerSeen, setOfferSeen] = useState(false);
  const switches = dataSwitchSummary().map((s) => {
    const lock = lockOf(s.key);
    const on = valueInForce(s.key, doc) === true;
    // The switch shows the saved choice; what the guide says is in force is the engine's own.
    return { ...s, lock, on, inForce: waitsForEngine(lock) ? engineInForce(engine) === true : on };
  });
  const steps = welcomeSteps(
    engine,
    offerSeen,
    switchesState(
      switches.map((s) => s.inForce),
      engine,
    ),
    switches.some((s) => s.key === HTTPS_SWITCH && s.inForce),
  );
  const index = Math.min(at, steps.length - 1);
  const step = steps[index];
  const last = index === steps.length - 1;
  const canPause = welcomeAdguard(engine);
  const busy = engine.adguard === "stopping";

  const go = (to: number) => {
    setAt(to);
    // Reaching the offer keeps it on screen when the pause ends it.
    if (steps[to]?.id === "adguard") setOfferSeen(true);
  };

  // The guide fills the content area: the step sits in the middle, one readable column wide,
  // and the step count and buttons sit at the foot, where they stay put from step to step.
  return (
    <main className="page-container flex min-h-full flex-1 flex-col pb-6" data-welcome-step={step.id}>
      <div className="flex flex-1 flex-col items-center justify-center py-10">
        <div className="flex w-full max-w-2xl flex-col gap-6">
          <h1 className="text-center text-title-lg text-on-surface-muted">Welcome</h1>
          <EmptyState line={step.title} body={step.body} className="p-0" />
          {step.id === "switches" && (
            <ul aria-label="What can change traffic" className="flex flex-col gap-5">
              {switches.map((s) => {
                const labelId = `welcome-${s.key}-label`;
                const helpId = `welcome-${s.key}-help`;
                return (
                  <li key={s.key} className="flex items-start justify-between gap-6" data-welcome-switch={s.key}>
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                      <p id={labelId} className="text-body-strong text-on-surface">
                        {s.label}
                      </p>
                      <p id={helpId} className="text-label text-on-surface-muted">
                        {s.help}
                      </p>
                      {s.lock && <LockNote lock={s.lock} />}
                    </div>
                    <div className="flex min-h-11 shrink-0 items-center">
                      <Switch checked={s.on} disabled={s.lock !== null} data-pending={waitsForEngine(s.lock) ? "" : undefined} className={waitsForEngine(s.lock) ? PENDING_SWITCH_CLASS : undefined} onCheckedChange={(v) => set(s.key, v)} aria-labelledby={labelId} aria-describedby={helpId} />
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
          {step.id === "https" && (
            <Link href={HTTPS_HREF} onClick={onDone} className="text-label text-primary underline-offset-4 hover:underline" data-welcome-https="">
              {HTTPS_INVITE.link}
            </Link>
          )}
          {step.id === "adguard" && (
            <div className="flex flex-col items-start gap-2" data-welcome-adguard="">
              {canPause ? (
                <>
                  <p className="text-label text-on-surface-muted break-words">{ADGUARD_PAUSE_TEXT}</p>
                  <Button variant="secondary" disabled={busy} onClick={() => void stopAdguard()}>
                    {busy ? "Pausing AdGuard" : "Pause AdGuard"}
                  </Button>
                </>
              ) : (
                <p role="status" className="text-label text-on-surface-muted break-words">
                  AdGuard is not running now. You can start it again in Settings.
                </p>
              )}
              {engine.actionError && (
                <p role="alert" className="text-label text-blocked break-words">
                  {engine.actionError}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
      <div className="mx-auto flex w-full max-w-2xl flex-wrap items-center justify-between gap-2">
        <p className="text-label text-on-surface-muted tabular">
          Step {index + 1} of {steps.length}
        </p>
        <div className="flex flex-wrap justify-end gap-2">
          {!last && (
            <Button variant="ghost" onClick={onDone}>
              Skip
            </Button>
          )}
          {index > 0 && (
            <Button variant="secondary" onClick={() => go(index - 1)}>
              Back
            </Button>
          )}
          {last ? <Button onClick={onDone}>Finish</Button> : <Button onClick={() => go(index + 1)}>Next</Button>}
        </div>
      </div>
    </main>
  );
}
