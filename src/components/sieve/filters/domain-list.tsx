"use client";

import { ShieldCheck, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { normalizeDomain } from "@/core/rules";

/** A titled list of host names: add one (pasting a URL works), remove one. Knows no setting, so any list of hosts can use it. */
export function DomainList({
  title,
  description,
  hosts,
  onAdd,
  onRemove,
  disabled,
}: {
  title: string;
  description: string;
  hosts: readonly string[];
  onAdd: (host: string) => void;
  onRemove: (host: string) => void;
  disabled: boolean;
}) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = (e: FormEvent) => {
    e.preventDefault();
    const host = normalizeDomain(typed);
    if (!host.ok) return setError(host.error);
    setError(null);
    setTyped("");
    onAdd(host.host);
  };
  return (
    <Card title={title} icon={<ShieldCheck strokeWidth={1.75} />}>
      <div className="flex flex-col gap-3" data-domain-list="">
        <p className="text-label text-on-surface-muted">{description}</p>
        <form onSubmit={add} className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Input
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              disabled={disabled}
              aria-label={`Add to ${title}`}
              placeholder="example.com"
              spellCheck={false}
              className="h-9 flex-1 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset"
            />
            <Button type="submit" variant="secondary" disabled={disabled || typed.trim() === ""}>
              Add
            </Button>
          </div>
          {error && (
            <p role="alert" className="text-label text-blocked">
              {error}
            </p>
          )}
        </form>
        {hosts.length > 0 && (
          <ul aria-label={title} className="flex flex-col gap-1">
            {hosts.map((h) => (
              <li key={h} className="flex min-h-11 items-center justify-between gap-2" data-domain={h}>
                <span className="min-w-0 font-mono text-mono break-all text-on-surface">{h}</span>
                <IconButton label={`Remove ${h}`} disabled={disabled} onClick={() => onRemove(h)}>
                  <X strokeWidth={1.75} />
                </IconButton>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
