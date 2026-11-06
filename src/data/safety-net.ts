/**
 * The read-only safety net (spec slice 4: it stays until no supported build
 * can have pointed a machine). At load and every WINDOWS_DNS_POLL_MS it reads
 * which DNS servers Windows uses; while `strandedAdapters` finds an adapter
 * asking 127.0.0.1 or ::1, one Home banner says so (STRANDED_DNS_TEXT), with
 * no action: the way out is Windows' own network settings, which the text
 * names. Sieve never changes Windows DNS (docs/conventions.md, section 0).
 *
 * The newest reading stays in this closure: only the banner depends on it. A
 * failed read keeps it (unknown is not "nothing points at Sieve"). A banner
 * the user dismissed comes back only after the problem went away and returned.
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { STRANDED_DNS_TEXT, WINDOWS_DNS_POLL_MS, strandedAdapters } from "@/core/dns";
import type { NoticeBus } from "@/core/notices";
import type { Clock } from "./poller";
import { parseWindowsDns, WINDOWS_DNS_VERSION, type AdapterDns, type WindowsDns } from "./protocol";

export interface WindowsDnsSource {
  /** Read only: the DNS servers each active Windows adapter uses. */
  windowsDns(): Promise<WindowsDns>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriWindowsDns(invoke: Invoke = tauriInvoke): WindowsDnsSource {
  return { windowsDns: async () => parseWindowsDns(await invoke<unknown>("windows_dns")) };
}

/** Windows' own DNS: two active adapters, documentation addresses only. */
const OWN: readonly AdapterDns[] = [
  { alias: "Wi-Fi", index: 12, servers: ["192.0.2.53", "2001:db8::53"] },
  { alias: "Ethernet 2", index: 7, servers: ["198.51.100.53", "203.0.113.53"] },
];

/** ?pointed=1: the Wi-Fi adapter asks the loopback addresses, as an old build left it. */
const POINTED: readonly AdapterDns[] = [{ ...OWN[0], servers: ["127.0.0.1", "::1"] }, OWN[1]];

export function createMockWindowsDns({ pointed = false }: { pointed?: boolean } = {}): WindowsDnsSource {
  return {
    windowsDns: async () => ({
      v: WINDOWS_DNS_VERSION,
      adapters: (pointed ? POINTED : OWN).map((a) => ({ ...a, servers: [...a.servers] })),
    }),
  };
}

export interface SafetyNetDeps {
  source: WindowsDnsSource;
  notices: NoticeBus;
  clock: Clock;
}

export interface SafetyNet {
  /** Read now and on the cadence, and keep the banner true. Returns the undo. */
  bind(): () => void;
}

export function createSafetyNet({ source, notices, clock }: SafetyNetDeps): SafetyNet {
  return {
    bind() {
      let disposed = false;
      let timer: unknown = null;
      let banner: number | null = null;
      let windows: WindowsDns | null = null;

      const read = async () => {
        try {
          windows = await source.windowsDns();
        } catch {
          // Read only and for a warning: the last reading stands.
        }
      };

      const update = () => {
        const stranded = strandedAdapters(windows).length > 0;
        if (stranded && banner === null) banner = notices.push({ kind: "error", surface: "banner", text: STRANDED_DNS_TEXT });
        else if (!stranded && banner !== null) {
          notices.dismiss(banner);
          banner = null;
        }
      };

      const cycle = async () => {
        await read();
        if (disposed) return;
        update();
        timer = clock.setTimeout(() => {
          timer = null;
          void cycle();
        }, WINDOWS_DNS_POLL_MS);
      };

      void cycle();
      return () => {
        disposed = true;
        if (timer !== null) clock.clearTimeout(timer);
        timer = null;
        if (banner !== null) notices.dismiss(banner);
        banner = null;
      };
    },
  };
}
