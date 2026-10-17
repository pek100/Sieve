"use client";

import { useState } from "react";
import { SearchField } from "@/components/sieve/primitives/search-field";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Page } from "@/components/sieve/shell/page";
import { Button } from "@/components/ui/button";
import { DNS_SWITCH } from "@/core/dns";
import { settingDef } from "@/core/settings/registry";
import { DnsCard } from "./dns-card";
import { SettingRow } from "./setting-row";

/** The section that owns the DNS switch shows the DNS filter card under its rows. */
const DNS_SECTION = settingDef(DNS_SWITCH).section;
import { TransferMenu } from "./transfer-menu";
import { useSettingsView } from "./use-settings-view";

/**
 * Settings (plan rows 68 to 70 and 6): every row is rendered from the
 * registry, so a new setting appears here with no UI change. A rail of
 * sections on the left (a wrapping row of chips under 960 px), one column of
 * about 720 px, search across label, help, key and options, and an overflow
 * menu with export, import and reset. The section that owns the DNS switch
 * also carries the DNS filter card (status, counters, list, Windows DNS).
 */
export function SettingsScreen() {
  const [query, setQuery] = useState("");
  const view = useSettingsView(query);

  return (
    <Page title="Settings" action={<TransferMenu view={view} />}>
      <div className="grid grid-cols-1 gap-6 two:grid-cols-[12rem_minmax(0,720px)] two:justify-center">
        <nav aria-label="Settings sections" className="two:sticky two:top-20 two:self-start">
          <ul className="flex flex-wrap gap-2 two:flex-col two:gap-1">
            {view.sections.map((s) => (
              <li key={s.id}>
                <a
                  href={`#section-${s.id}`}
                  className="relative flex h-9 items-center overflow-hidden rounded-full bg-surface-2 px-4 text-label text-on-surface-muted hover:text-on-surface two:bg-transparent"
                >
                  {s.label}
                  <StateLayer />
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-8">
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
            view.sections.map((s) => (
              <div key={s.id} id={`section-${s.id}`} className="scroll-mt-20">
                <Card title={s.label}>
                  <div className="flex flex-col">
                    {s.keys.map((k) => (
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
                {s.id === DNS_SECTION && (
                  <div className="pt-8">
                    <DnsCard lockOf={view.lockOf} />
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </Page>
  );
}
