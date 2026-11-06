"use client";

import { ShieldOff } from "lucide-react";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { SearchField } from "@/components/sieve/primitives/search-field";
import { Card } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Button } from "@/components/ui/button";
import { EXCLUSIONS_SHOWN, FLOOR_LINE, NOT_IN_FORCE_LINE, REASON_GROUP_TEXT } from "@/core/exclusions";
import { ExclusionsAdd } from "./exclusions-add";
import { ExclusionsRow } from "./exclusions-row";
import { useExclusions } from "./use-exclusions";

const plural = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/**
 * Settings > Filtering, "Not decrypted" (plan 8.2): every site Sieve leaves
 * encrypted, why, and what can be done about it. The user's own lines show with the
 * engine stopped too. Floor facts cannot be removed, so they are no rows: one line
 * under the list names them.
 */
export function ExclusionsGroup() {
  const m = useExclusions();
  const filtered = m.group !== "all" || m.app !== null || m.query.trim() !== "";
  return (
    <Card title="Not decrypted" icon={<ShieldOff strokeWidth={1.75} />}>
      <div className="flex flex-col gap-4" data-exclusions-group="">
        {!m.inForce && (
          <p className="text-label text-on-surface-muted" data-exclusions-not-in-force="">
            {NOT_IN_FORCE_LINE}
          </p>
        )}
        {m.error && (
          <p role="alert" className="text-label text-blocked break-words" data-exclusions-error="">
            {m.error}
          </p>
        )}
        {m.actionError && (
          <p role="alert" className="text-label text-blocked break-words" data-exclusions-action-error="">
            {m.actionError}
          </p>
        )}
        <ExclusionsAdd model={m} />
        {m.total > 0 && (
          <div className="flex flex-col gap-3">
            {m.groups.length > 2 && (
              <div className="max-w-full overflow-x-auto">
                <Segmented size="sm" label="Filter by reason" value={m.group} onChange={m.setGroup} items={m.groups.map((g) => ({ value: g, label: REASON_GROUP_TEXT[g] }))} />
              </div>
            )}
            <SearchField value={m.query} onChange={m.setQuery} label="Search sites not decrypted" placeholder="Search by site, app or reason" />
            {m.app !== null && (
              <div className="flex flex-wrap items-center gap-2" data-exclusions-app={m.app}>
                <span className="min-w-0 flex-auto text-label break-all text-on-surface-muted">What applies to {m.appInfo(m.app).name}</span>
                {m.canTryAll && (
                  <Button variant="secondary" size="sm" onClick={m.tryAll}>
                    Try decrypting all again
                  </Button>
                )}
                <Button variant="ghost" size="sm" onClick={m.clearApp}>
                  Show every app
                </Button>
              </div>
            )}
          </div>
        )}
        {m.shown.length > 0 ? (
          <ul aria-label="Sites not decrypted" className="flex flex-col">
            {m.shown.map((row) => (
              <ExclusionsRow key={row.key} row={row} model={m} />
            ))}
          </ul>
        ) : filtered ? (
          <EmptyState
            line="No row matches"
            body="Nothing here fits that filter and search."
            action={
              <Button variant="secondary" onClick={m.clearFilters}>
                Show every row
              </Button>
            }
          />
        ) : (
          <p className="text-label text-on-surface-muted" data-exclusions-empty="">
            No site is on this list yet.
          </p>
        )}
        {m.hidden > 0 && (
          <p className="text-caption text-on-surface-faint" data-exclusions-more="">
            {m.hidden.toLocaleString("en-US")} more, search to narrow. The first {EXCLUSIONS_SHOWN} that match are listed.
          </p>
        )}
        {m.skipped > 0 && (
          <p className="text-caption text-on-surface-faint" data-exclusions-skipped="">
            {plural(m.skipped, "row", "rows")} could not be read.
          </p>
        )}
        <p className="text-caption text-on-surface-faint" data-exclusions-floor="">
          {FLOOR_LINE}
        </p>
      </div>
    </Card>
  );
}
