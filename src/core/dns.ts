/**
 * The read-only DNS safety net, the pure part. Sieve never points Windows DNS
 * anywhere (docs/conventions.md, "Sieve off means a normal network"), and it
 * has no listener on port 53 any more; an old build may have left an adapter
 * asking 127.0.0.1 or ::1, and such an adapter's lookups go nowhere. The
 * safety net only says so (src/data/safety-net.ts). It stays until no
 * supported build can have pointed a machine.
 */
import type { WindowsDns } from "@/data/protocol";

/** How often Windows DNS is read (read only) for the safety net, from startup on. */
export const WINDOWS_DNS_POLL_MS = 30_000;

/** The loopback DNS servers an old Sieve build pointed Windows at. */
export const LOOPBACK_DNS: ReadonlySet<string> = new Set(["127.0.0.1", "::1"]);

/**
 * The active adapters whose DNS servers include 127.0.0.1 or ::1, in Windows'
 * order, each once. `windows` null (not read yet, or unreadable) is unknown,
 * not "nothing pointed": it decides nothing.
 */
export function strandedAdapters(windows: WindowsDns | null): string[] {
  if (windows === null) return [];
  const out: string[] = [];
  for (const a of windows.adapters) {
    if (a.servers.some((s) => LOOPBACK_DNS.has(s)) && !out.includes(a.alias)) out.push(a.alias);
  }
  return out;
}

/** The safety notice, word for word. It points only to Windows' own network settings. */
export const STRANDED_DNS_TEXT =
  "Windows is set to use Sieve for DNS, but nothing of Sieve's answers there, so sites may not load. Set DNS back to automatic in Windows network settings.";
