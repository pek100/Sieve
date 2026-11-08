"use client";

import { EyeOff } from "lucide-react";
import { useMemo } from "react";
import { LockNote } from "@/components/sieve/settings/setting-row";
import { useSettingsView, valueInForce, type Lock } from "@/components/sieve/settings/use-settings-view";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useHydrated } from "@/hooks/use-hydrated";
import { CUSTOM } from "@/core/profiles";
import { readValue, writeValue } from "@/core/settings/document";
import { TRACKING_LEVELS, settingDef, type Section, type SettingKey } from "@/core/settings/registry";
import { RECOMMENDED_TRACKING, TRACKING_KEYS, TRACKING_TEXT, trackingLevel, trackingValues } from "@/core/tracking";
import { ChoiceList } from "./choice-list";

const NO_BLOCKS: ReadonlySet<Section> = new Set();

/** Said once above the options while none of them can act. */
export const TRACKING_WAITS_TEXT = "None of these is in effect yet, so each shows off. The level shown is kept, and takes effect once HTTPS decryption is on.";

/**
 * Tracking protection: a level (Standard, Strict, or Custom when the options
 * say neither) over options each stated by its effect, with what it can break.
 * The level is derived from the options; picking one writes them all in one
 * change with an Undo. Every option is locked the way Settings locks a row,
 * and while they all share one reason it is said once, above them.
 */
export function TrackingBlock() {
  const view = useSettingsView("", NO_BLOCKS);
  const { doc, lockOf } = view;
  const locks = useMemo(() => new Map(TRACKING_KEYS.map((k) => [k, lockOf(k)] as const)), [lockOf]);
  // The password is said once, at the top of the screen; here what would still hold each option.
  const reasons = useMemo(() => new Map([...locks].map(([k, l]) => [k, l?.kind === "password" ? l.beneath : l] as const)), [locks]);
  // Stored settings are read in the window only: the first paint matches the prerendered page.
  const hydrated = useHydrated();
  const level = hydrated ? trackingLevel((k) => readValue(doc, k)) : null;
  const shared: Lock | null = useMemo(() => {
    const all = [...reasons.values()];
    return all.every((l) => l !== null && JSON.stringify(l) === JSON.stringify(all[0])) ? all[0] : null;
  }, [reasons]);
  const anyLocked = [...locks.values()].some((l) => l !== null);

  const choose = (next: (typeof TRACKING_LEVELS)[number]) => {
    const values = trackingValues(next);
    const target = TRACKING_KEYS.reduce((d, k) => writeValue(d, k, values[k]), doc);
    view.apply(target, next === RECOMMENDED_TRACKING ? "Tracking protection is back to Standard, the recommended level" : `Tracking protection set to ${TRACKING_TEXT[next].label}`);
  };
  const choices = TRACKING_LEVELS.map((v) => ({ value: v, label: TRACKING_TEXT[v].label, note: v === RECOMMENDED_TRACKING ? "Recommended" : undefined, text: TRACKING_TEXT[v].text }));

  return (
    <Card title="Tracking protection" icon={<EyeOff strokeWidth={1.75} />}>
      <div className="flex flex-col gap-4" data-tracking="">
        {shared && (
          <div className="flex flex-col gap-1" data-tracking-locked="">
            <LockNote lock={shared} />
            <p className="text-label text-on-surface-muted">{TRACKING_WAITS_TEXT}</p>
          </div>
        )}
        <ChoiceList label="Tracking protection level" choices={choices} current={level} onChoose={choose} disabled={anyLocked} />
        {level === CUSTOM && (
          <div className="flex flex-wrap items-center gap-2" data-tracking-custom="">
            <p className="text-label text-on-surface-muted">{TRACKING_TEXT.custom.text}</p>
            <Button variant="ghost" size="sm" disabled={anyLocked} onClick={() => choose(RECOMMENDED_TRACKING)}>
              Back to Standard
            </Button>
          </div>
        )}
        <ul aria-label="Tracking protection options" className="flex flex-col gap-4">
          {TRACKING_KEYS.map((k) => (
            // A locked option shows what is in effect, off, never the wish it keeps: the level above says the choice.
            <TrackingOption key={k} k={k} lock={locks.get(k) ?? null} reason={reasons.get(k) ?? null} showLock={shared === null} on={hydrated && locks.get(k) === null && valueInForce(k, doc, null) === true} onSet={(v) => view.set(k, v)} />
          ))}
        </ul>
      </div>
    </Card>
  );
}

function TrackingOption({ k, lock, reason, showLock, on, onSet }: { k: SettingKey; lock: Lock | null; reason: Lock | null; showLock: boolean; on: boolean; onSet: (on: boolean) => void }) {
  const d = settingDef(k);
  const labelId = `tracking-${k}-label`;
  return (
    <li className="flex min-h-11 items-start justify-between gap-3" data-tracking-option={k}>
      <div className="flex min-w-0 flex-1 flex-col">
        <span id={labelId} className="text-body text-on-surface">
          {d.label}
        </span>
        <span className="text-label text-on-surface-muted">{d.help}</span>
        {d.breaks && (
          <span className="text-label text-on-surface-muted" data-breaks="">
            <span className="text-on-surface">Can break:</span> {d.breaks}
          </span>
        )}
        {showLock && reason && <LockNote lock={reason} />}
      </div>
      <Switch checked={on} disabled={lock !== null} onCheckedChange={onSet} aria-labelledby={labelId} />
    </li>
  );
}
