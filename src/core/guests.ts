/**
 * "Virtual machines and WSL" in Apps: one row per VM an exact NAT match named,
 * plus one for forwarded traffic whose VM could not be named. Read from the
 * engine's Status, so the group exists only once forwarded traffic was seen.
 * A row's Off lands in `apps.levels` under the engine's `vm:` key, like an
 * app's, and survives until the row returns.
 */
import type { EngineGuest } from "@/data/protocol";

export const VM_GROUP_LABEL = "Virtual machines and WSL";
export const VM_UNIDENTIFIED_LABEL = "Unidentified virtual machine traffic";
export const VM_NOTE = "Filtered by domain only";
/** The switch's tooltip: a VM row is never charted, so an app's Off text would be false here. */
export const VM_OFF_MEANS = "Off: Sieve does not filter this virtual machine's traffic.";

/** The fields search reads (`matchesQuery`); a VM has a name and no exe. */
export interface GuestRow {
  key: string;
  name: string;
  exes: string[];
  /** Flows open now. */
  open: number;
}

/** The engine's rows in its order (named first, the unidentified row last), with their labels. */
export function guestRows(guests: readonly EngineGuest[] | null | undefined): GuestRow[] {
  return (guests ?? []).map((g) => ({ key: g.key, name: g.vm ?? VM_UNIDENTIFIED_LABEL, exes: [], open: g.open ?? 0 }));
}
