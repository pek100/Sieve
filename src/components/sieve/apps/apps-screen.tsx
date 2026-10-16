"use client";

import { AppWindow, Info } from "lucide-react";
import { useMemo, useState } from "react";
import { BentoGrid, BentoItem } from "@/components/sieve/shell/bento-grid";
import { Card, type CardState } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Page } from "@/components/sieve/shell/page";
import { matchesQuery, sections } from "@/core/apps-actions";
import { AddApp } from "./add-app";
import { AppDetailSheet } from "./app-detail";
import { AppSectionView, type RowActions } from "./app-list";
import { AppSearch } from "./app-search";
import { BulkMenu } from "./bulk-menu";
import { useAppParam } from "./use-app-param";
import { useApps } from "./use-apps";

/**
 * The Apps screen: every app grouped by derived category, a level per app,
 * the detail sheet deep-linked by ?app=<key>, add and remove, bulk actions.
 */
export function AppsScreen() {
  const model = useApps();
  const [openKey, setOpenKey] = useAppParam();
  const [query, setQuery] = useState("");

  const visible = useMemo(() => model.apps.filter((a) => matchesQuery(a, query)), [model.apps, query]);
  const grouped = useMemo(() => sections(visible), [visible]);
  const filtered = query.trim() !== "";
  const waiting = model.phase === "starting" && model.apps.length === 0;

  const actions: RowActions = {
    levelOf: model.levelOf,
    lockedReason: model.lockedReason,
    setLevel: model.setLevel,
    open: setOpenKey,
    unpin: model.unpin,
  };

  const state: CardState = waiting
    ? { kind: "loading" }
    : model.phase === "error" && model.apps.length === 0
      ? { kind: "error", message: model.error ?? "Could not read connections" }
      : { kind: "ready" };

  const locked = model.lockedReason("sieve");
  const n = model.sievedNow;

  return (
    <Page
      title="Apps"
      action={
        <>
          <AddApp onAdd={model.pin} />
          <BulkMenu onWatchAll={model.watchAll} onStopAll={model.stopAll} onReset={model.resetLevels} />
        </>
      }
    >
      <BentoGrid>
        <BentoItem span="full">
          <Card
            title="All apps"
            icon={<AppWindow strokeWidth={1.75} />}
            tone="mint"
            state={state}
            action={
              <span className="tabular text-label text-on-surface-muted" data-testid="sieved-count">
                {n} being sieved
              </span>
            }
          >
            <div className="flex flex-col gap-4">
              <AppSearch value={query} onChange={setQuery} />
              {locked && (
                <p className="flex items-center gap-2 text-label text-on-surface-muted" data-testid="sieve-locked">
                  <Info className="size-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
                  Sieve: {locked}. Apps can be watched or off for now.
                </p>
              )}
              {filtered && visible.length === 0 ? (
                <EmptyState line="Nothing by that name" body={`No app or path matches "${query.trim()}".`} />
              ) : (
                <div className="flex flex-col gap-2">
                  {grouped.map((s) => (
                    <AppSectionView key={s.category} section={s} actions={actions} filtered={filtered} />
                  ))}
                </div>
              )}
            </div>
          </Card>
        </BentoItem>
      </BentoGrid>
      <AppDetailSheet
        appKey={openKey}
        app={openKey === null ? undefined : model.apps.find((a) => a.key === openKey)}
        loading={waiting}
        actions={actions}
        onClose={() => setOpenKey(null)}
      />
    </Page>
  );
}
