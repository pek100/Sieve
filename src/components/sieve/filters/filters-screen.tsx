"use client";

import { LockedNote } from "@/components/sieve/lock/locked-note";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { isShut } from "@/core/lock";
import { ALLOWLIST_TEXT } from "@/core/rules";
import { useFilters } from "@/hooks/use-filters";
import { useLock } from "@/hooks/use-lock";
import { DomainList } from "./domain-list";
import { ListCatalogue } from "./list-catalogue";
import { RulesEditor } from "./rules-editor";

export const NOT_APPLIED_TEXT = "No filter list is in force yet: the engine has not loaded any. These choices are saved and reach the engine while it runs.";
const BLOCKLIST_TEXT = "Connections to these sites and their subdomains are closed for every app that is on, whatever the filter lists say.";

/**
 * Filters: the list catalogue beside the user's own rules and domain lists. The
 * catalogue comes from the engine's table through the filter list seam and its
 * counts from the engine's report; the choices are settings, the same ones the
 * engine is sent. While the password holds, all of it stays readable and no
 * control takes a change.
 */
export function FiltersScreen() {
  const model = useFilters();
  const { state: lockState } = useLock();
  const shut = isShut(lockState.phase);
  const pending = model.nothingInForce;
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
          <DomainList title="Blocklist" description={BLOCKLIST_TEXT} hosts={model.blocklist} onAdd={model.addBlocked} onRemove={model.removeBlocked} disabled={shut} />
        </GridRegion>
      </LayoutGrid>
    </Page>
  );
}
