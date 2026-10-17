"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { bindDesktop, bindDns, bindSampling, createBrowserRuntime, type Runtime } from "./runtime";

const RuntimeContext = createContext<Runtime | null>(null);

/** Provides the window's runtime and keeps sampling, the desktop shell and the DNS filter bound to the settings. */
export function SieveProvider({ runtime, children }: { runtime?: Runtime; children: ReactNode }) {
  const [rt] = useState(() => runtime ?? createBrowserRuntime());
  useEffect(() => bindSampling(rt), [rt]);
  useEffect(() => bindDesktop(rt), [rt]);
  useEffect(() => bindDns(rt), [rt]);
  return <RuntimeContext.Provider value={rt}>{children}</RuntimeContext.Provider>;
}

export function useRuntime(): Runtime {
  const rt = useContext(RuntimeContext);
  if (!rt) throw new Error("useRuntime must be used inside <SieveProvider>");
  return rt;
}
