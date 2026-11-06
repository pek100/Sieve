"use client";

import { SearchField } from "@/components/sieve/primitives/search-field";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { LOG_FILTERS, LOG_FILTER_TEXT, type LogFilter } from "@/core/log";

const ITEMS = LOG_FILTERS.map((f) => ({ value: f, label: LOG_FILTER_TEXT[f] }));

/** The filters and the search, on one line where they fit. */
export function LogToolbar({ filter, onFilter, query, onQuery }: { filter: LogFilter; onFilter: (f: LogFilter) => void; query: string; onQuery: (q: string) => void }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {/* Four equal cells at 375 leave "Not decrypted" no room at the label size. */}
      <Segmented
        label="Show"
        items={ITEMS}
        value={filter}
        onChange={(v) => onFilter(v as LogFilter)}
        className="max-[640px]:w-full [&>button]:max-[640px]:px-0 [&>button]:max-[640px]:text-caption"
      />
      <SearchField value={query} onChange={onQuery} label="Search the log" placeholder="Search hosts, apps, rules, lists" className="min-w-0 flex-1 basis-60" />
    </div>
  );
}
