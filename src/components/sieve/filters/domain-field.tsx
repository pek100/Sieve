"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { normalizeDomain } from "@/core/rules";

/**
 * The form that adds one host name to a list: pasting a URL works, a bad name says
 * why. `onAdd` may answer with its own reason to refuse. `children` sits beside the
 * button, for a list that asks one thing more.
 */
export function DomainField({
  label,
  disabled,
  onAdd,
  children,
}: {
  /** Accessible name of the input. */
  label: string;
  disabled: boolean;
  onAdd: (host: string) => string | null | void;
  children?: ReactNode;
}) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const add = (e: FormEvent) => {
    e.preventDefault();
    const host = normalizeDomain(typed);
    if (!host.ok) return setError(host.error);
    const refused = onAdd(host.host);
    setError(refused ?? null);
    if (!refused) setTyped("");
  };
  return (
    <form onSubmit={add} className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          disabled={disabled}
          aria-label={label}
          placeholder="example.com"
          spellCheck={false}
          className="h-9 min-w-0 flex-1 basis-48 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset"
        />
        {children}
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
  );
}
