"use client";

import { useState } from "react";
import { SearchField } from "@/components/sieve/primitives/search-field";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { GridRegion, LayoutGrid } from "@/components/sieve/shell/layout-grid";
import { Page } from "@/components/sieve/shell/page";
import { Button } from "@/components/ui/button";
import { DNS_SWITCH } from "@/core/dns";
import { ENGINE_ANCHOR } from "@/core/engine";
import { isAvailable, settingDef, type Section } from "@/core/settings/registry";
import { cn } from "@/lib/utils";
import { DNS_CARD_KEYS, DnsCard } from "./dns-card";
import { EngineCard } from "./engine-card";
import { SettingRow } from "./setting-row";
import { TransferMenu } from "./transfer-menu";
import { useSettingsView } from "./use-settings-view";

/** The section that owns the DNS switch shows the filtering blocks under its rows: the DNS filter (while available) and the engine. */
const FILTERING_SECTION = settingDef(DNS_SWITCH).section;
/** Sections with blocks of their own, listed even when none of their keys is available. */
const BLOCK_SECTIONS: ReadonlySet<Section> = new Set([FILTERING_SECTION]);

/**
 * Settings (plan rows 68 to 70 and 6): every row is rendered from the
 * registry, so a new setting appears here with no UI change, and an
 * unavailable one (`unavailableUntil`) has no row. On the page grid: a rail
 * of sections (3 columns, starting on the page title's line; a wrapping row
 * of chips under 960 px) and the content (9 columns, ending on the header
 * actions' line) with the search, the section titles and the rows on its
 * edges. Search covers label, help, key and options; the overflow menu has
 * export, import and reset. The section that owns the DNS switch also
 * carries the DNS filter card (status, counters, list, upstreams, the safety
 * notice) while that switch is available, and the engine (EngineCard, read
 * only, anchor ENGINE_ANCHOR); a key the DNS card edits itself
 * (DNS_CARD_KEYS) has no row of its own, so each setting has one owner on
 * the screen.
 */
export function SettingsScreen() {
  const [query, setQuery] = useState("");
  const view = useSettingsView(query, BLOCK_SECTIONS);
  const dnsCard = isAvailable(DNS_SWITCH);

  return (
    <Page title="Settings" action={<TransferMenu view={view} />}>
      <LayoutGrid>
        <GridRegion span={3} className="two:sticky two:top-[4rem] two:self-start">
          <nav aria-label="Settings sections">
            <ul className="flex flex-wrap gap-2 two:flex-col two:gap-1">
              {view.sections.map((s) => (
                <li key={s.id}>
                  <a
                    href={`#section-${s.id}`}
                    className="relative flex h-9 items-center overflow-hidden rounded-full bg-surface-2 px-4 text-label text-on-surface-muted hover:text-on-surface two:rounded-sm two:bg-transparent two:px-0"
                  >
                    {s.label}
                    <StateLayer />
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </GridRegion>
        <GridRegion span={9} className="flex flex-col gap-8">
          <SearchField value={query} onChange={setQuery} label="Search settings" placeholder="Search settings" />
          {view.sections.length === 0 ? (
            <EmptyState
              line="No setting matches"
              body={`Nothing is called "${query.trim()}". Try another word.`}
              action={
                <Button variant="secondary" onClick={() => setQuery("")}>
                  Show every setting
                </Button>
              }
            />
          ) : (
            view.sections.map((s) => {
              const keys = s.keys.filter((k) => !DNS_CARD_KEYS.has(k));
              const filtering = s.id === FILTERING_SECTION;
              return (
                <div key={s.id} id={`section-${s.id}`} className="scroll-mt-[4rem]">
                  {keys.length > 0 && (
                    <Card title={s.label}>
                      <div className="flex flex-col gap-4">
                        {keys.map((k) => (
                          <SettingRow
                            key={k}
                            k={k}
                            doc={view.doc}
                            lock={view.lockOf(k)}
                            route={s.route}
                            onSet={view.set}
                            onReset={view.reset}
                          />
                        ))}
                      </div>
                    </Card>
                  )}
                  {filtering && (
                    <div className={cn("flex flex-col gap-8", keys.length > 0 && "pt-8")}>
                      {dnsCard && <DnsCard lockOf={view.lockOf} />}
                      <div id={ENGINE_ANCHOR} className="scroll-mt-[4rem]">
                        <EngineCard />
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </GridRegion>
      </LayoutGrid>
    </Page>
  );
}
