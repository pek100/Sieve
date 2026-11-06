"use client";

import { ShieldCheck, X } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Card } from "@/components/sieve/shell/card";
import { DomainField } from "./domain-field";

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
  return (
    <Card title={title} icon={<ShieldCheck strokeWidth={1.75} />}>
      <div className="flex flex-col gap-3" data-domain-list="">
        <p className="text-label text-on-surface-muted">{description}</p>
        <DomainField label={`Add to ${title}`} disabled={disabled} onAdd={onAdd} />
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
