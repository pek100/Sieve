"use client";

import { Info } from "lucide-react";
import { useMemo, useState } from "react";
import { CardBody, CardBoundary, type CardState } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { matchesQuery, sections } from "@/core/apps-actions";
import { AddApp } from "./add-app";
import { AppDetailSheet } from "./app-detail";
import { AppSectionView, type RowActions } from "./app-list";
import { AppSearch } from "./app-search";
import { BulkMenu } from "./bulk-menu";
import { useAppParam } from "./use-app-param";
import { useApps } from "./use-apps";
import { VmGroup } from "./vm-group";

/**
 * The Apps screen: every app grouped by derived category, on or off per app,
 * the detail sheet deep-linked by ?app=<key>, add and remove, bulk actions.
 * Flat on the page grid (no card): the count beside the title, the search,
 * then the groups, edge to edge of the page container. Virtual machines come
 * first, once the engine has seen their traffic.
 */
export function AppsScreen() {
  const model = useApps();
  const [openKey, setOpenKey] = useAppParam();
  const [query, setQuery] = useState("");

  const visible = useMemo(() => model.apps.filter((a) => matchesQuery(a, query)), [model.apps, query]);
  const grouped = useMemo(() => sections(visible), [visible]);
  const visibleGuests = useMemo(() => model.guests.filter((g) => matchesQuery(g, query)), [model.guests, query]);
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
      meta={
        <span className="tabular text-label text-on-surface-muted" data-testid="sieved-count">
          {n} being sieved
        </span>
      }
      action={
        <>
          <AddApp onAdd={model.pin} />
          <BulkMenu onSieveAll={model.sieveAll} onOffAll={model.offAll} />
        </>
      }
    >
      <CardBoundary title="Apps">
        {/* On the page grid: the search takes half the width, the list runs edge to edge so every toggle ends on the header actions' line. */}
        <LayoutGrid>
          <GridRegion span={6}>
            <AppSearch value={query} onChange={setQuery} />
          </GridRegion>
          {!model.globalOn && (
            <GridRegion span={12}>
              <p className="flex items-center gap-2 text-label text-on-surface-muted" data-testid="sieving-off">
                <Info className="size-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
                Sieving is off for every app. Turn it on in the top bar.
              </p>
            </GridRegion>
          )}
          <GridRegion span={12}>
            <section aria-label="All apps" aria-busy={state.kind === "loading" || undefined} className="flex flex-col">
              <CardBody state={state}>
                {filtered && visible.length === 0 && visibleGuests.length === 0 ? (
                  <EmptyState line="Nothing by that name" body={`No app or path matches "${query.trim()}".`} />
                ) : (
                  <div className="flex flex-col gap-6">
                    <VmGroup rows={visibleGuests} actions={actions} />
                    {grouped.map((s) => (
                      <AppSectionView key={s.category} section={s} actions={actions} filtered={filtered} />
                    ))}
                  </div>
                )}
              </CardBody>
            </section>
          </GridRegion>
        </LayoutGrid>
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
