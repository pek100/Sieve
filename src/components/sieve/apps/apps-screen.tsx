"use client";

import { Info } from "lucide-react";
import { useMemo, useState } from "react";
import { CardBody, CardBoundary, type CardState } from "@/components/sieve/shell/card";
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
 * The Apps screen: every app grouped by derived category, on or off per app,
 * the detail sheet deep-linked by ?app=<key>, add and remove, bulk actions.
 * Flat on the page (no card): search and the count, then the groups.
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
    isOn: model.isOn,
    setOn: model.setOn,
    open: setOpenKey,
    unpin: model.unpin,
  };

  const state: CardState = waiting
    ? { kind: "loading" }
    : model.phase === "error" && model.apps.length === 0
      ? { kind: "error", message: model.error ?? "Could not read connections" }
      : { kind: "ready" };

  const n = model.sievedNow;

  return (
    <Page
      title="Apps"
      action={
        <>
          <AddApp onAdd={model.pin} />
          <BulkMenu onSieveAll={model.sieveAll} onOffAll={model.offAll} />
        </>
      }
    >
      <CardBoundary title="Apps">
        <section aria-label="All apps" aria-busy={state.kind === "loading" || undefined} className="flex max-w-[880px] flex-col gap-4">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <div className="min-w-0 flex-1 basis-60">
              <AppSearch value={query} onChange={setQuery} />
            </div>
            <span className="tabular text-label text-on-surface-muted" data-testid="sieved-count">
              {n} being sieved
            </span>
          </div>
          {!model.globalOn && (
            <p className="flex items-center gap-2 text-label text-on-surface-muted" data-testid="sieving-off">
              <Info className="size-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
              Sieving is off for every app. Turn it on in the top bar.
            </p>
          )}
          <CardBody state={state}>
            {filtered && visible.length === 0 ? (
              <EmptyState line="Nothing by that name" body={`No app or path matches "${query.trim()}".`} />
            ) : (
              <div className="flex flex-col gap-4">
                {grouped.map((s) => (
                  <AppSectionView key={s.category} section={s} actions={actions} filtered={filtered} />
                ))}
              </div>
            )}
          </CardBody>
        </section>
      </CardBoundary>
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
