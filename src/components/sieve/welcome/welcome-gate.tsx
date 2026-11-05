"use client";

import type { ReactNode } from "react";
import { useWelcome } from "@/hooks/use-welcome";
import { WelcomeScreen } from "./welcome-screen";

/** The first-run guide takes over the content area while it is due; the top bar stays. Everything else renders as ever. */
export function WelcomeGate({ children }: { children: ReactNode }) {
  const { show, done } = useWelcome();
  return show ? <WelcomeScreen onDone={done} /> : <>{children}</>;
}
