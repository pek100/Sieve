"use client";

import { LockedNote } from "@/components/sieve/lock/locked-note";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { nothingLoaded } from "@/core/filter-lists";
import { isShut } from "@/core/lock";
import { ALLOWLIST_TEXT } from "@/core/rules";
import { useFilters } from "@/hooks/use-filters";
import { useLock } from "@/hooks/use-lock";
import { DomainList } from "./domain-list";
import { ListCatalogue } from "./list-catalogue";
import { RulesEditor } from "./rules-editor";

export const NOT_APPLIED_TEXT = "Sieve blocks nothing yet. These choices are saved, and the engine starts using them in a later version.";

/**
 * Filters: the list catalogue beside the user's own rules and allowlist. The
 * catalogue and its counts come from the engine's table through the filter list
 * seam; the choices are settings. While the password holds, all of it stays
 * readable and no control takes a change.
 */
export function FiltersScreen() {
  const model = useFilters();
  const { state: lockState } = useLock();
  const shut = isShut(lockState.phase);
  const pending = model.catalogue === null || nothingLoaded(model.catalogue.lists);
  return (
    <Page title="Filters">
      <LayoutGrid>
        {(pending || shut) && (
          <GridRegion span={12} className="flex flex-col gap-1">
            {pending && (
              <p className="text-body text-on-surface-muted" data-filters-pending="">
                {NOT_APPLIED_TEXT}
              </p>
            )}
            {shut && <LockedNote phase={lockState.phase} />}
          </GridRegion>
        )}
        <GridRegion span={6}>
          <ListCatalogue model={model} disabled={shut} />
        </GridRegion>
        <GridRegion span={6} className="flex flex-col gap-8">
          <RulesEditor saved={model.rules} onSave={model.saveRules} disabled={shut} />
          <DomainList title="Allowlist" description={ALLOWLIST_TEXT} hosts={model.allowlist} onAdd={model.addAllowed} onRemove={model.removeAllowed} disabled={shut} />
        </GridRegion>
      </LayoutGrid>
    </Page>
  );
}
