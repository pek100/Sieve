"use client";

import { X } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { Monogram } from "@/components/sieve/apps/monogram";
import { Button } from "@/components/ui/button";
import { canTryAgain, exclusionReasonWords, retryWords, type ExclusionView } from "@/core/exclusions";
import type { ExclusionsModel } from "./use-exclusions";

/** The apps a row is for: each with its icon, or "All apps". */
function RowApps({ apps, appInfo }: { apps: readonly string[]; appInfo: ExclusionsModel["appInfo"] }) {
  if (apps.length === 0) return <span className="text-label text-on-surface-muted">All apps</span>;
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
      {apps.map((file) => {
        const app = appInfo(file);
        return (
          <span key={file} className="flex min-w-0 items-center gap-2 text-label text-on-surface-muted">
            <AppIcon exe={app.exe} size={16}>
              <Monogram appKey={app.key} name={app.name} size={16} />
            </AppIcon>
            <span className="min-w-0 break-all">{app.name}</span>
          </span>
        );
      })}
    </span>
  );
}

/** One thing that is not decrypted: its pattern, who for, why, and what can be done about it. A list's line offers nothing. */
export function ExclusionsRow({ row, model }: { row: ExclusionView; model: Pick<ExclusionsModel, "appInfo" | "remove" | "tryAgain"> }) {
  const retried = retryWords(row.retries);
  return (
    <li className="flex min-h-11 flex-wrap items-center justify-between gap-x-4 gap-y-1 py-1" data-exclusion-row={row.reason}>
      <div className="flex min-w-0 flex-1 basis-64 flex-col gap-1">
        <span className="min-w-0 font-mono text-mono break-all text-on-surface">{row.line}</span>
        <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <RowApps apps={row.apps ?? []} appInfo={model.appInfo} />
          <span className="min-w-0 text-label text-on-surface-muted">
            {exclusionReasonWords(row.reason)}
            {retried && `, ${retried}`}
          </span>
        </span>
      </div>
      {row.userLine !== null && (
        <IconButton label={`Remove ${row.userLine}`} onClick={() => model.remove(row)}>
          <X strokeWidth={1.75} />
        </IconButton>
      )}
      {canTryAgain(row) && (
        <Button variant="ghost" size="sm" onClick={() => model.tryAgain(row)} aria-label={`Try decrypting ${row.line} again`}>
          Try decrypting again
        </Button>
      )}
    </li>
  );
}
