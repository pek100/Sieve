/**
 * The DNS seam: every call the window makes about the DNS filter and the
 * Windows DNS reads goes through one DnsSource. `tauri` calls the Rust
 * commands (src-tauri/src/dns/commands.rs, windns.rs, adguard.rs) and
 * validates every answer; `mock` (dns-mock.ts) is a deterministic stand-in
 * for the browser, tests and e2e. A Tauri error is passed through as is,
 * never replaced by mock data. Nothing here changes Windows DNS: Sieve never
 * does.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseDnsStatus, parseSelfCheck, parseWindowsDns, type DnsStatus, type SelfCheck, type WindowsDns } from "./protocol";

/** What dns_start takes (keys absent take Rust's defaults: listen on 127.0.0.1:53 and [::1]:53). */
export interface DnsStartConfig {
  upstreams: readonly string[];
}

export interface DnsSource {
  readonly kind: "mock" | "tauri";
  start(config: DnsStartConfig): Promise<DnsStatus>;
  stop(): Promise<DnsStatus>;
  status(): Promise<DnsStatus>;
  selfCheck(): Promise<SelfCheck>;
  /** Forward everything and block nothing (true), or filter again (false). Fails when not running. */
  setPassThrough(on: boolean): Promise<DnsStatus>;
  /** Read only: the DNS servers each active Windows adapter uses. */
  windowsDns(): Promise<WindowsDns>;
  /** Read only: an AdGuard process (Adguard.exe, AdguardSvc.exe) is running. */
  adguardRunning(): Promise<boolean>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriDns(invoke: Invoke = tauriInvoke): DnsSource {
  return {
    kind: "tauri",
    start: async (config) => parseDnsStatus(await invoke<unknown>("dns_start", { config: { upstreams: config.upstreams } })),
    stop: async () => parseDnsStatus(await invoke<unknown>("dns_stop")),
    status: async () => parseDnsStatus(await invoke<unknown>("dns_status")),
    selfCheck: async () => parseSelfCheck(await invoke<unknown>("dns_self_check")),
    setPassThrough: async (on) => parseDnsStatus(await invoke<unknown>("dns_set_pass_through", { on })),
    windowsDns: async () => parseWindowsDns(await invoke<unknown>("windows_dns")),
    adguardRunning: async () => {
      const v = await invoke<unknown>("adguard_running");
      if (typeof v !== "boolean") throw new Error("adguard_running must answer a boolean");
      return v;
    },
  };
}
