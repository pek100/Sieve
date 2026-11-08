"use client";

import Link from "next/link";
import { useState } from "react";
import { LockedNote } from "@/components/sieve/lock/locked-note";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { ENGINE_HREF } from "@/core/engine";
import { isShut } from "@/core/lock";
import { ALLOWLIST_TEXT } from "@/core/rules";
import { trackingOffered } from "@/core/tracking";
import { useRuntime } from "@/hooks/sieve-provider";
import { useFilters } from "@/hooks/use-filters";
import { useHydrated } from "@/hooks/use-hydrated";
import { useLock } from "@/hooks/use-lock";
import { useSieve } from "@/hooks/use-sieve";
import { DomainList } from "./domain-list";
import { ListCatalogue } from "./list-catalogue";
import { OwnLists } from "./own-lists";
import { ProtectionLevel } from "./protection-level";
import { RulesDialog, type RulesTarget } from "./rules-dialog";
import { RulesEditor } from "./rules-editor";
import { TrackingBlock } from "./tracking-block";

export const NOT_APPLIED_TEXT = "No filter list is in force yet: the engine has not loaded any. These choices are saved and reach the engine while it runs.";
const BLOCKLIST_TEXT = "Connections to these sites and their subdomains are closed for every app that is on, whatever the filter lists say.";

/** The languages this computer uses, best first; none before hydration, so the first paint matches the server's. */
function useLanguages(): readonly string[] {
  const hydrated = useHydrated();
  return hydrated && typeof navigator !== "undefined" ? (navigator.languages ?? [navigator.language]) : [];
}

/** "Now" for "Updated 5 min ago": the window's clock, read at each store change (the poller ticks it). */
const useNow = () => {
  const { clock } = useRuntime();
  useSieve((s) => s.snapshots.length);
  return clock.now();
};

/**
 * Filters: one choice at the top (the protection level), every list under it
 * by what it is for, the person's own lists, then tracking protection (once
 * the engine carries it out) and the person's own rules. The catalogue comes from the engine's table and its
 * counts from the engine's report; every choice is a setting, the same one the
 * engine is sent, and the levels are derived from them. While the password
 * holds, all of it stays readable and no control takes a change.
 */
export function FiltersScreen() {
  const model = useFilters();
  const { state: lockState } = useLock();
  const shut = isShut(lockState.phase);
  const pending = model.nothingInForce;
  const languages = useLanguages();
  const nowMs = useNow();
  const [rulesOf, setRulesOf] = useState<RulesTarget | null>(null);
  return (
    <Page title="Filters">
      <LayoutGrid>
        {(pending || shut) && (
          <GridRegion span={12} className="flex flex-col gap-1">
            {pending && (
              <p className="text-body text-on-surface-muted" data-filters-pending="">
                {NOT_APPLIED_TEXT}{" "}
                <Link href={ENGINE_HREF} className="text-primary underline-offset-4 hover:underline">
                  See the engine in Settings
                </Link>
              </p>
            )}
            {shut && <LockedNote phase={lockState.phase} />}
          </GridRegion>
        )}
        <GridRegion span={6} className="flex flex-col gap-8">
          <ProtectionLevel model={model} disabled={shut} />
          <ListCatalogue model={model} disabled={shut} nowMs={nowMs} languages={languages} onRules={setRulesOf} />
        </GridRegion>
        <GridRegion span={6} className="flex flex-col gap-8">
          <OwnLists model={model} disabled={shut} nowMs={nowMs} onRules={setRulesOf} />
          {trackingOffered() && <TrackingBlock />}
          <RulesEditor saved={model.rules} onSave={model.saveRules} disabled={shut} />
          <DomainList title="Allowlist" description={ALLOWLIST_TEXT} hosts={model.allowlist} onAdd={model.addAllowed} onRemove={model.removeAllowed} disabled={shut} />
          <DomainList title="Blocklist" description={BLOCKLIST_TEXT} hosts={model.blocklist} onAdd={model.addBlocked} onRemove={model.removeBlocked} disabled={shut} />
        </GridRegion>
      </LayoutGrid>
      <RulesDialog target={rulesOf} load={model.listRules} onClose={() => setRulesOf(null)} />
    </Page>
  );
}
