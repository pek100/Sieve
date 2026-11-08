"use client";

import { FileUp, ListPlus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { MAX_CUSTOM_LISTS } from "@/core/custom-lists";
import { ENGINE_AWAY_TEXT, type FiltersModel } from "@/hooks/use-filters";
import { useHydrated } from "@/hooks/use-hydrated";
import { ListMenu, ListStatusLine } from "./list-group";
import type { RulesTarget } from "./rules-dialog";

export const OWN_LISTS_TEXT = `Add a list by its address, or from a file on this computer, up to ${MAX_CUSTOM_LISTS}. Sieve checks each one when it downloads or imports it, and never lets one run the trusted scriptlets the built-in lists may use.`;

const hostOf = (url: string) => url.replace(/^https:\/\//, "").split(/[/?#]/)[0] ?? url;

/** The person's own lists: add one by address or from a file, then each with its state, its menu and its switch. */
export function OwnLists({ model, disabled, nowMs, onRules }: { model: FiltersModel; disabled: boolean; nowMs: number; onRules: (target: RulesTarget) => void }) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const reason = model.engineAnswers ? null : ENGINE_AWAY_TEXT;
  // Stored settings are read in the window only: the first paint matches the prerendered page.
  const hydrated = useHydrated();
  const own = hydrated ? model.own : [];

  const run = async (act: () => Promise<string | null>, clear: boolean) => {
    setBusy(true);
    try {
      const why = await act();
      setError(why);
      if (why === null && clear) setTyped("");
    } finally {
      setBusy(false);
    }
  };
  const add = (e: FormEvent) => {
    e.preventDefault();
    void run(() => model.addOwnUrl(typed), true);
  };

  return (
    <Card title="Your own lists" icon={<ListPlus strokeWidth={1.75} />}>
      <div className="flex flex-col gap-3" data-own-lists="">
        <p className="text-label text-on-surface-muted">{OWN_LISTS_TEXT}</p>
        <form onSubmit={add} className="flex flex-wrap items-center gap-2">
          <Input
            value={typed}
            onChange={(e) => {
              setTyped(e.target.value);
              setError(null);
            }}
            disabled={disabled}
            aria-label="List address"
            placeholder="https://example.com/list.txt"
            spellCheck={false}
            className="h-9 min-w-0 flex-1 basis-60 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset"
          />
          <Button type="submit" variant="secondary" disabled={disabled || busy || typed.trim() === ""}>
            Add list
          </Button>
          <Button type="button" variant="ghost" disabled={disabled || busy || reason !== null} onClick={() => void run(model.importOwnFile, false)}>
            <FileUp strokeWidth={1.75} />
            Import a file
          </Button>
        </form>
        {reason !== null && <p className="text-label text-on-surface-muted">Importing a file needs the engine. {reason}</p>}
        {error && (
          <p role="alert" className="text-label text-blocked" data-own-error="">
            {error}
          </p>
        )}
        {own.length > 0 && (
          <ul aria-label="Your own lists" className="flex flex-col gap-3">
            {own.map((l) => (
              <li key={l.id} className="flex min-h-11 items-start justify-between gap-3" data-own-list={l.id}>
                <div className="flex min-w-0 flex-1 flex-col">
                  <span className="text-body text-on-surface break-words">{l.title}</span>
                  <span className="text-label text-on-surface-muted break-all">{l.url === null ? "From a file" : <span className="font-mono text-mono">{hostOf(l.url)}</span>}</span>
                  <ListStatusLine report={l.report} fetch={l.fetch} nowMs={nowMs} />
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <ListMenu
                    title={l.title}
                    reason={reason}
                    disabled={disabled}
                    actions={{
                      onRules: () => onRules({ id: l.id, title: l.title }),
                      onRefresh: l.url !== null && l.enabled ? () => void model.refreshList(l.id).then(setError) : undefined,
                      onRemove: () => model.removeOwn(l.id),
                    }}
                  />
                  <Switch checked={l.enabled} disabled={disabled} onCheckedChange={(on) => model.setOwnOn(l.id, on)} aria-label={l.title} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
