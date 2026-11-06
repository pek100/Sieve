"use client";

import { ArrowDown, ArrowUp, X } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { MAX_UPSTREAMS, UPSTREAM_KINDS, composeUpstream, parseUpstream, upstreamIdentity, upstreamReadback, type UpstreamKind } from "@/core/upstream";
import { useEngine } from "@/hooks/use-sieve";

const KIND_LABELS: Record<UpstreamKind, string> = { doh: "DoH", dot: "DoT", doq: "DoQ" };
const NOT_AN_ADDRESS = "Not an encrypted address. Type a host name or IP address, or a full https://, tls:// or quic:// address.";
const ALREADY_LISTED = "Already listed.";
const FULL = `The engine takes at most ${MAX_UPSTREAMS} servers.`;
/** At phone width a control is a thumb's target, 44 px. */
const TOUCH_ICON = "max-[640px]:size-11";
const TOUCH_HEIGHT = "max-[640px]:h-11";

/** Whatever the store held, as a list: this row must render, never crash. */
const listOf = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : []);

const moved = (list: readonly string[], from: number, to: number) => {
  const next = [...list];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
};

/**
 * The encrypted DNS servers: added with their protocol, removed, and put in the
 * order they are tried for failover, up and down buttons so it works by keyboard
 * and by touch. `composeUpstream` and `parseUpstream` are the one grammar; the
 * engine's own answer is read back under the list. The only entry cannot be removed:
 * the engine refuses an empty list.
 */
export function UpstreamRow({ label, value, disabled, onChange, reset }: { label: string; value: unknown; disabled: boolean; onChange: (next: string[]) => void; reset: ReactNode }) {
  const engine = useEngine();
  const list = listOf(value);
  const [kind, setKind] = useState<UpstreamKind>("doh");
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const shownKind = parseUpstream(typed)?.kind ?? kind;
  const full = list.length >= MAX_UPSTREAMS;
  const readback = upstreamReadback(list, engine.heldUpstreams);

  // A move to the end disables the button just pressed: focus stays in the row.
  const rows = useRef<HTMLOListElement>(null);
  const movedTo = useRef<number | null>(null);
  useEffect(() => {
    const at = movedTo.current;
    movedTo.current = null;
    if (at === null || (document.activeElement && document.activeElement !== document.body)) return;
    rows.current?.children[at]?.querySelector<HTMLButtonElement>("button:not(:disabled)")?.focus();
  });
  const move = (from: number, to: number) => {
    movedTo.current = to;
    onChange(moved(list, from, to));
  };

  const add = (e: FormEvent) => {
    e.preventDefault();
    const composed = composeUpstream(kind, typed);
    if (composed === null) return setError(NOT_AN_ADDRESS);
    const identity = upstreamIdentity(composed.upstream);
    if (list.some((raw) => { const held = parseUpstream(raw); return held !== null && upstreamIdentity(held) === identity; })) return setError(ALREADY_LISTED);
    setError(null);
    setTyped("");
    onChange([...list, composed.address]);
  };

  return (
    <div className="flex min-w-0 flex-col gap-3" data-upstream-editor="">
      <ol ref={rows} aria-label={`${label}, tried in this order`} className="flex flex-col gap-1">
        {list.map((raw, i) => (
          <li key={`${raw}#${list.slice(0, i).filter((other) => other === raw).length}`} data-upstream={raw} className="flex min-h-11 items-center gap-1">
            <span className="min-w-0 flex-1 font-mono text-mono break-all text-on-surface">{raw}</span>
            <IconButton label={`Move ${raw} up`} className={TOUCH_ICON} disabled={disabled || i === 0} onClick={() => move(i, i - 1)}>
              <ArrowUp strokeWidth={1.75} />
            </IconButton>
            <IconButton label={`Move ${raw} down`} className={TOUCH_ICON} disabled={disabled || i === list.length - 1} onClick={() => move(i, i + 1)}>
              <ArrowDown strokeWidth={1.75} />
            </IconButton>
            <IconButton label={`Remove ${raw}`} className={TOUCH_ICON} disabled={disabled || list.length === 1} onClick={() => onChange(list.filter((_, at) => at !== i))}>
              <X strokeWidth={1.75} />
            </IconButton>
          </li>
        ))}
      </ol>
      {readback && (
        <p className="text-label break-words text-on-surface-muted" data-upstream-readback="">
          {readback}
        </p>
      )}
      {engine.dnsError && (
        <p role="alert" className="text-label break-words text-blocked" data-engine-dns-error="">
          {engine.dnsError}
        </p>
      )}
      <form onSubmit={add} className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <Segmented
            label="DNS protocol"
            size="touch"
            items={UPSTREAM_KINDS.map((k) => ({ value: k, label: KIND_LABELS[k], disabled }))}
            value={shownKind}
            onChange={setKind}
          />
          <Input
            value={typed}
            onChange={(e) => {
              setTyped(e.target.value);
              setError(null);
            }}
            disabled={disabled}
            aria-label={`Add to ${label}`}
            placeholder="dns.example"
            spellCheck={false}
            className={`h-9 min-w-0 flex-1 basis-40 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset ${TOUCH_HEIGHT}`}
          />
          <Button type="submit" variant="secondary" className={TOUCH_HEIGHT} disabled={disabled || full || typed.trim() === ""}>
            Add
          </Button>
          {reset}
        </div>
        {error && (
          <p role="alert" className="text-label break-words text-blocked">
            {error}
          </p>
        )}
        {full && <p className="text-label text-on-surface-muted">{FULL}</p>}
      </form>
    </div>
  );
}
