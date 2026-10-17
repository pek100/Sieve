"use client";

import { SearchField } from "@/components/sieve/primitives/search-field";

/** The Apps screen's search: the shared inset pill search with its own words. */
export function AppSearch({
  value,
  onChange,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  className?: string;
}) {
  return (
    <SearchField value={value} onChange={onChange} label="Search apps" placeholder="Search apps or paths" className={className} />
  );
}
