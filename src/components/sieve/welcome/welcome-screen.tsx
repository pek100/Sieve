"use client";

import { useState } from "react";
import { Page } from "@/components/sieve/shell/page";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ADGUARD_PAUSE_TEXT } from "@/core/engine";
import { dataSwitchSummary, welcomeAdguard, welcomeSteps } from "@/core/welcome";
import { useEngine, useEngineActions } from "@/hooks/use-sieve";

/**
 * The first-run guide. It explains; it never changes the network: no step writes
 * a data switch, they show read only and off, and the one action is the existing
 * pause offer, on the person's click. Skip is always one click (plan D14).
 */
export function WelcomeScreen({ onDone }: { onDone: () => void }) {
  const engine = useEngine();
  const { stopAdguard } = useEngineActions();
  const [at, setAt] = useState(0);
  const [offerSeen, setOfferSeen] = useState(false);
  const steps = welcomeSteps(engine, offerSeen);
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

  return (
    <Page title="Welcome">
      <div className="flex flex-col gap-6 py-6" data-welcome-step={step.id}>
        <EmptyState line={step.title} body={step.body} className="p-0" />
        {step.id === "switches" && (
          <ul aria-label="What can change traffic" className="flex flex-col gap-3">
            {dataSwitchSummary().map((s) => (
              <li key={s.key} className="flex min-h-11 items-center justify-between gap-4" data-welcome-switch={s.key}>
                <div className="min-w-0">
                  <p className="text-body-strong text-on-surface">{s.label}</p>
                  <p className="text-label text-on-surface-muted">{s.help}</p>
                </div>
                <Switch checked={false} disabled aria-label={s.label} />
              </li>
            ))}
          </ul>
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
        <div className="flex flex-wrap items-center justify-between gap-2">
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
      </div>
    </Page>
  );
}
