"use client";

import { Search, X } from "lucide-react";
import { useRef } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { cn } from "@/lib/utils";

/** Inset pill search (D's search well). Escape or the clear button empties it. */
export function SearchField({
  value,
  onChange,
  label,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  /** Accessible name of the input. */
  label: string;
  placeholder: string;
  className?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <div
      className={cn(
        "flex h-10 items-center gap-2 rounded-full bg-inset pr-1 pl-4 shadow-inset focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-primary",
        className,
      )}
    >
      <Search className="size-4 shrink-0 text-on-surface-muted" strokeWidth={1.75} aria-hidden="true" />
      <input
        ref={input}
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape" && value) {
            e.preventDefault();
            e.stopPropagation();
            onChange("");
          }
        }}
        placeholder={placeholder}
        aria-label={label}
        spellCheck={false}
        className="h-full min-w-0 flex-1 bg-transparent text-body text-on-surface outline-none placeholder:text-on-surface-faint focus-visible:outline-none [&::-webkit-search-cancel-button]:hidden"
      />
      {value && (
        <IconButton
          label="Clear search"
          className="size-8 [&_svg]:size-4"
          onClick={() => {
            onChange("");
            input.current?.focus();
          }}
        >
          <X strokeWidth={1.75} />
        </IconButton>
      )}
    </div>
  );
}
