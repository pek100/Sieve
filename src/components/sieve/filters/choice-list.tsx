"use client";

import { Check } from "lucide-react";
import { useRef, type KeyboardEvent } from "react";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { cn } from "@/lib/utils";

export interface Choice<V extends string> {
  value: V;
  label: string;
  /** Plain words after the label, such as "Recommended". */
  note?: string;
  text: string;
}

/**
 * One choice out of a few, each said in a sentence: a radio group of pressable
 * rows (the profile and the tracking level). The value is derived by the
 * caller; `current` may be one no row offers (Custom), and then no row is
 * checked and the first holds the tab stop. Arrows move and choose, as a radio
 * group does.
 */
export function ChoiceList<V extends string>({
  label,
  choices,
  current,
  onChoose,
  disabled,
}: {
  label: string;
  choices: readonly Choice<V>[];
  current: string | null;
  onChoose: (value: V) => void;
  disabled: boolean;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const at = choices.findIndex((c) => c.value === current);
  const move = (e: KeyboardEvent, i: number) => {
    const step = e.key === "ArrowDown" || e.key === "ArrowRight" ? 1 : e.key === "ArrowUp" || e.key === "ArrowLeft" ? -1 : 0;
    if (step === 0) return;
    e.preventDefault();
    const next = (i + step + choices.length) % choices.length;
    refs.current[next]?.focus();
    onChoose(choices[next].value);
  };
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-col gap-1">
      {choices.map((c, i) => {
        const checked = i === at;
        return (
          <button
            key={c.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={checked}
            tabIndex={checked || (at < 0 && i === 0) ? 0 : -1}
            disabled={disabled}
            data-choice={c.value}
            onClick={() => !checked && onChoose(c.value)}
            onKeyDown={(e) => move(e, i)}
            className={cn(
              "relative flex min-h-11 w-full items-start gap-3 overflow-hidden rounded-md px-3 py-2 text-left transition-colors duration-(--motion-fast) ease-standard disabled:opacity-(--disabled-content)",
              checked && "bg-selected",
            )}
          >
            <span aria-hidden="true" className={cn("flex size-5 shrink-0 items-center justify-center rounded-full border border-outline-strong", checked && "border-primary bg-primary text-on-primary")}>
              {checked && <Check className="size-3.5" strokeWidth={2.5} />}
            </span>
            <span className="flex min-w-0 flex-col">
              <span className="text-body-strong text-on-surface">
                {c.label}
                {c.note && <span className="text-label font-normal text-on-surface-muted"> {c.note}</span>}
              </span>
              <span className="text-label text-on-surface-muted">{c.text}</span>
            </span>
            <StateLayer />
          </button>
        );
      })}
    </div>
  );
}
