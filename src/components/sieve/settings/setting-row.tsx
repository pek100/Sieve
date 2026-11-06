"use client";

import { Lock as LockIcon } from "lucide-react";
import Link from "next/link";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { RouteDef } from "@/core/routes";
import { readValue, type SettingsDoc } from "@/core/settings/document";
import { defaultValue, settingDef, type SettingKey } from "@/core/settings/registry";
import { formatNumber, formatValue, numberChoices } from "@/core/settings/transfer";
import type { Lock } from "./use-settings-view";

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const emptyDefault = (k: SettingKey) => {
  const d = defaultValue(k);
  return Array.isArray(d) ? d.length === 0 : typeof d === "object" && d !== null && Object.keys(d).length === 0;
};

function LockNote({ lock }: { lock: Lock }) {
  return (
    <p data-lock={lock.kind} className="flex items-start gap-2 pt-1 text-label text-on-surface-muted">
      <LockIcon aria-hidden="true" className="size-4 shrink-0 text-warning" strokeWidth={1.75} />
      <span className="min-w-0">
        {lock.kind === "desktop" ? (
          "Only the desktop app can change this."
        ) : lock.kind === "engine" ? (
          lock.reason
        ) : lock.checking ? (
          `Needs ${lock.label} to pass its self check.`
        ) : (
          `Needs ${lock.label}, which is off.`
        )}
      </span>
    </p>
  );
}

/**
 * One setting, its control chosen by the registry kind: enum segmented,
 * boolean and data switch as a switch, number as a select of its steps, map
 * and list as a summary (they are edited on their own screen) with a reset.
 * A locked row shows its control disabled at the value in force, with the
 * reason under the help text (an engine lock: the engine's own value, never
 * the stored wish it could not send).
 */
export function SettingRow({
  k,
  doc,
  lock,
  route,
  onSet,
  onReset,
}: {
  k: SettingKey;
  doc: SettingsDoc;
  lock: Lock | null;
  route: RouteDef | undefined;
  onSet: (key: SettingKey, value: unknown) => void;
  onReset: (key: SettingKey) => void;
}) {
  const d = settingDef(k);
  // The value in force: what the engine itself holds for a setting it carries
  // out but cannot take now (off when it did not say), else the stored value.
  const value = lock?.kind === "engine" ? lock.inForce === true : readValue(doc, k);
  const labelId = `setting-${k}-label`;
  const helpId = `setting-${k}-help`;
  const disabled = lock !== null;

  let control: React.ReactNode;
  switch (d.kind) {
    case "enum":
      control = (
        <Segmented
          label={d.label}
          items={d.options.map((o) => ({ value: o, label: capital(o), disabled }))}
          value={String(value)}
          onChange={(v) => onSet(k, v)}
        />
      );
      break;
    case "boolean":
    case "dataSwitch": {
      control = (
        <Switch
          checked={value === true}
          disabled={disabled}
          onCheckedChange={(v) => onSet(k, v)}
          aria-labelledby={labelId}
          aria-describedby={helpId}
        />
      );
      break;
    }
    case "number":
      control = (
        <Select value={String(value)} onValueChange={(v) => onSet(k, Number(v))} disabled={disabled}>
          <SelectTrigger aria-labelledby={labelId} className="h-9 w-28 rounded-full bg-inset px-3 text-label tabular">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {numberChoices(k).map((n) => (
              <SelectItem key={n} value={String(n)} className="tabular">
                {formatNumber(n, d.unit)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      );
      break;
    case "map":
    case "list":
      control = (
        <div className="flex min-w-0 items-center gap-2">
          <span className="min-w-0 text-label text-on-surface-muted tabular break-words">{formatValue(k, value)}</span>
          {!same(value, defaultValue(k)) && (
            // Back to the default: "Clear" when the default is empty, "Reset" when it has entries.
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onReset(k)}
              aria-label={`${emptyDefault(k) ? "Clear" : "Reset"} ${d.label}`}
            >
              {emptyDefault(k) ? "Clear" : "Reset"}
            </Button>
          )}
          {route && (
            <Button variant="secondary" size="sm" asChild>
              <Link href={route.href}>Open {route.label}</Link>
            </Button>
          )}
        </div>
      );
      break;
  }

  return (
    <div
      id={`setting-${k}`}
      data-setting={k}
      role="group"
      aria-labelledby={labelId}
      className="flex min-h-11 flex-wrap items-center justify-between gap-x-4 gap-y-2"
    >
      <div className="min-w-0 flex-1 basis-60">
        <p id={labelId} className="text-body-strong text-on-surface">
          {d.label}
        </p>
        <p id={helpId} className="text-label text-on-surface-muted">
          {d.help}
        </p>
        {lock && <LockNote lock={lock} />}
      </div>
      <div className="flex max-w-full min-w-0 items-center">{control}</div>
    </div>
  );
}
