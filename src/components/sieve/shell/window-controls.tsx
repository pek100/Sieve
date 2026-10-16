"use client";

import { Minus, Square, X } from "lucide-react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { useRuntime } from "@/hooks/sieve-provider";
import { useHydrated } from "@/hooks/use-hydrated";

async function win() {
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  return getCurrentWindow();
}

/** Minimise, maximise and close for the frameless Tauri window. Renders nothing in a browser. */
export function WindowControls() {
  const { isTauri } = useRuntime();
  // The static prerender has no window; render only after hydration so the markup matches.
  const hydrated = useHydrated();
  if (!hydrated || !isTauri) return null;
  return (
    <div className="flex items-center gap-1">
      <IconButton label="Minimise" onClick={() => void win().then((w) => w.minimize())}>
        <Minus strokeWidth={1.75} />
      </IconButton>
      <IconButton label="Maximise" onClick={() => void win().then((w) => w.toggleMaximize())}>
        <Square strokeWidth={1.75} className="size-4!" />
      </IconButton>
      <IconButton label="Close" className="hover:text-blocked" onClick={() => void win().then((w) => w.close())}>
        <X strokeWidth={1.75} />
      </IconButton>
    </div>
  );
}
