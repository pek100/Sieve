"use client";

import type { ReactNode } from "react";
import { TooltipProvider } from "@/components/ui/tooltip";
import type { Runtime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { useThemeSync } from "@/hooks/use-theme";
import { NoticeToaster } from "./notice-toaster";
import { TopBar } from "./top-bar";

function ThemeSync() {
  useThemeSync();
  return null;
}

/** The window: runtime, theme, top bar, the routed screen, toasts. Mounted once in the root layout. */
export function AppShell({ children, runtime }: { children: ReactNode; runtime?: Runtime }) {
  return (
    <SieveProvider runtime={runtime}>
      <ThemeSync />
      <TooltipProvider delayDuration={300}>
        <div className="flex min-h-dvh flex-col">
          <TopBar />
          {children}
        </div>
        <NoticeToaster />
      </TooltipProvider>
    </SieveProvider>
  );
}
