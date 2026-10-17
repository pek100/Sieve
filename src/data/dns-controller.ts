/**
 * The DNS controller: the one owner of DNS state (the store's `dns` part)
 * and the only caller of the DNS source. It follows two data switches:
 *
 * - `filtering.dns` (DNS_SWITCH). On: dns_start, then dns_self_check; a
 *   passed check is recorded in passedChecks. A failed start (port 53 busy)
 *   or a failed check turns the switch back off with a notice naming the
 *   error. Off: dns_stop, and when Windows points at Sieve, restore first;
 *   if that restore does not happen the filter stays on (stopping it would
 *   leave Windows asking a server that is gone).
 * - the global Sieving switch (GLOBAL_SWITCH). Off puts a running filter in
 *   pass-through (dns_set_pass_through): it keeps answering and forwards
 *   everything, so Windows DNS pointed here keeps working; on filters again.
 *   The filter is never stopped for it.
 * - `filtering.systemDns` (SYSTEM_DNS_SWITCH). It mirrors Windows: on load
 *   the switch is set from what Windows does, never the other way (no UAC
 *   prompt at startup). Only a change the user makes points or restores.
 *
 * Safety (conventions section 6): on load, when Windows points at loopback
 * and Sieve's backup exists, the filter is started whatever the switch says
 * (otherwise nothing resolves). If it cannot start, a banner with "Restore
 * my DNS" stays until it is dismissed or the restore works. Quitting while
 * Windows points at Sieve asks first (requestQuit, quit).
 *
 * dns_status is read every DNS_POLL_MS while the filter runs, with the
 * Windows DNS and AdGuard reads alongside. Time comes from the injected clock.
 */
import type { PassedChecks } from "@/core/checks";
import {
  DNS_POLL_MS,
  DNS_SWITCH,
  SYSTEM_DNS_SWITCH,
  UPSTREAMS_KEY,
  CHECK_DETAILS_AT,
  checkFailedLine,
  checkFailure,
  mustAskBeforeQuit,
  needsProxyAtStart,
  type DnsSlice,
} from "@/core/dns";
import type { NoticeBus } from "@/core/notices";
import { GLOBAL_SWITCH } from "@/core/policy";
import type { SieveStore } from "@/core/store";
import type { DnsSource } from "./dns-source";
import type { Clock } from "./poller";
import type { SelfCheck, SystemDnsState } from "./protocol";
import type { SettingsStore } from "./settings-store";

export interface DnsController {
  /** Load, apply the safety rule, then follow the switches. Returns the undo. */
  bind(): () => void;
  /** Point Windows at Sieve (the switch's on path; the DNS card's button calls it too). */
  point(): Promise<boolean>;
  /** Restore Windows DNS from the backup. */
  restore(): Promise<boolean>;
  /** Tray Quit or window close. Asks first while Windows points at Sieve; otherwise quits. */
  requestQuit(): void;
  /** The window should not close by itself now (the quit question is shown instead). */
  holdClose(): boolean;
  cancelQuit(): void;
  /** Answer to the quit question: restore then quit, or quit and leave Windows pointed here. */
  quit(how: "restore" | "keep"): Promise<void>;
}

export interface DnsControllerDeps {
  dns: DnsSource;
  store: SieveStore;
  settings: SettingsStore;
  notices: NoticeBus;
  checks: PassedChecks;
  clock: Clock;
  /** Ends the app; null where there is no app to end (the browser). */
  exit: (() => Promise<void>) | null;
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
/** A reconcile that keeps finding work after this many rounds stops: something keeps failing. */
const MAX_ROUNDS = 4;

export function createDnsController(d: DnsControllerDeps): DnsController {
  const { dns, store, settings, notices, checks, clock } = d;
  const get = (): DnsSlice => store.getState().dns;
  const set = (patch: Partial<DnsSlice>) => store.setDns(patch);
  let disposed = false;
  let loaded = false;
  let timer: unknown = null;
  let banner: number | null = null;

  // Every action and read runs one at a time, in order: a switch flipped
  // while a start is in flight waits for it, and a slow status read can never
  // land after a stop and say "running".
  let chain: Promise<unknown> = Promise.resolve();
  const serial = <T,>(fn: () => Promise<T>): Promise<T> => {
    const p = chain.then(fn);
    chain = p.catch(() => undefined);
    return p;
  };
  let reconcileQueued = false;
  const requestReconcile = () => {
    if (reconcileQueued) return;
    reconcileQueued = true;
    void serial(async () => {
      reconcileQueued = false;
      await reconcile();
    });
  };

  const running = () => get().status?.running === true;

  /** The system switch's live check: every adapter asks Sieve, and the filter passed its own. */
  const recordSystemCheck = (system: SystemDnsState | null) => {
    if (system !== null && system.interfaces.length > 0 && system.interfaces.every((i) => i.uses_sieve) && checks.has(DNS_SWITCH)) {
      checks.add(SYSTEM_DNS_SWITCH);
    } else {
      checks.delete(SYSTEM_DNS_SWITCH);
    }
  };

  // The system switch value Sieve last wrote to say what Windows does. A
  // switch that differs from Windows AND from this value was changed by the
  // user (an order); one that still equals it means Windows changed by
  // itself (someone ran restore-dns.ps1), and the switch just follows.
  let mirrored: boolean | null = null;

  /** Set the system switch to what Windows does (never read as an order). */
  const mirrorSystem = async (system: SystemDnsState | null) => {
    // Unknown is not "not pointed": the switch keeps its value.
    if (system === null) return;
    const pointed = system.pointed;
    mirrored = pointed;
    if (settings.get(SYSTEM_DNS_SWITCH) !== pointed) await settings.set(SYSTEM_DNS_SWITCH, pointed);
  };

  const readSystem = async (): Promise<SystemDnsState | null> => {
    try {
      const system = await dns.systemState();
      set({ system });
      recordSystemCheck(system);
      return system;
    } catch (e) {
      // The last reading stays: a failed read says nothing about Windows.
      set({ error: `Windows DNS could not be read: ${message(e)}` });
      return null;
    }
  };

  const readAdguard = async () => {
    try {
      set({ adguard: await dns.adguardRunning() });
    } catch {
      // Only a warning depends on it; an unreadable process list shows none.
      set({ adguard: false });
    }
  };

  const readStatus = async () => {
    try {
      set({ status: await dns.status() });
    } catch (e) {
      set({ error: `DNS filter status could not be read: ${message(e)}` });
    }
  };

  const stopPolling = () => {
    if (timer !== null) clock.clearTimeout(timer);
    timer = null;
  };

  const schedulePoll = () => {
    if (disposed || timer !== null || !running()) return;
    timer = clock.setTimeout(() => {
      timer = null;
      void serial(async () => {
        if (disposed || !running()) return;
        await Promise.all([readStatus(), readSystem(), readAdguard()]);
        if (disposed) return;
        if (running()) schedulePoll();
        // The filter stopped by itself: its check no longer stands.
        else checks.delete(DNS_SWITCH);
        // Windows may have changed by itself (restore-dns.ps1 run by hand).
        requestReconcile();
      });
    }, DNS_POLL_MS);
  };

  const failedCheck = (e: unknown): SelfCheck => ({
    pass: false,
    checks: [{ kind: "call", server: "", name: "", expect: "an answer from the filter", got: message(e), pass: false }],
  });

  /**
   * Start and self check. `safety`: started because Windows points here; a
   * failed check then keeps it running (stopping would end every lookup).
   */
  const turnOn = async (safety: boolean): Promise<{ started: boolean; error: string | null }> => {
    set({ busy: "start", error: null, check: null });
    try {
      set({ status: await dns.start({ upstreams: settings.get(UPSTREAMS_KEY) }) });
    } catch (e) {
      const m = message(e);
      set({ busy: null, error: m });
      if (!safety) {
        await settings.set(DNS_SWITCH, false);
        notices.push({ kind: "error", text: `DNS filtering could not start: ${m}` });
      }
      return { started: false, error: m };
    }
    set({ busy: "check" });
    let check: SelfCheck;
    try {
      check = await dns.selfCheck();
    } catch (e) {
      check = failedCheck(e);
    }
    // The check's own lookups are in the counters now.
    await readStatus();
    set({ check, busy: null });
    schedulePoll();
    if (check.pass) {
      checks.add(DNS_SWITCH);
      recordSystemCheck(get().system);
      if (!safety) notices.push({ kind: "success", text: "DNS filtering is on. It answers for every app once Windows uses Sieve for DNS." });
      return { started: true, error: null };
    }
    // Short and plain in the toast and the card; the technical replies stay
    // in the card's self check details (checkDetails).
    const where = checkFailure(check);
    const more = `Details in ${CHECK_DETAILS_AT}.`;
    if (safety) {
      set({ error: checkFailedLine(check) });
      notices.push({ kind: "error", text: `Sieve's DNS filter is running, but its self check failed ${where}. ${more}` });
      return { started: true, error: null };
    }
    set({ busy: "stop" });
    try {
      set({ status: await dns.stop() });
    } catch (e) {
      set({ error: message(e) });
    }
    stopPolling();
    set({ busy: null, error: checkFailedLine(check) });
    await settings.set(DNS_SWITCH, false);
    notices.push({ kind: "error", text: `DNS filtering could not start: its self check failed ${where}. ${more}` });
    return { started: false, error: checkFailedLine(check) };
  };

  /** Follow the global switch: pass everything through while it is off. */
  const passThrough = async (on: boolean) => {
    set({ busy: "pass" });
    try {
      set({ status: await dns.setPassThrough(on), busy: null });
    } catch (e) {
      set({ busy: null, error: `DNS filter could not ${on ? "pause" : "resume"} blocking: ${message(e)}` });
      // Read back what the filter does, so the next round compares with the truth.
      await readStatus();
      return false;
    }
    return true;
  };

  const restore = async (): Promise<boolean> => {
    set({ busy: "restore" });
    try {
      const system = await dns.restoreSystem();
      set({ system, busy: null, error: null });
      recordSystemCheck(system);
      await mirrorSystem(system);
      if (banner !== null) notices.dismiss(banner);
      banner = null;
      notices.push({ kind: "success", text: "Your DNS is restored: Windows uses its own DNS servers again." });
      return true;
    } catch (e) {
      const m = message(e);
      set({ busy: null, error: `Your DNS was not restored: ${m}` });
      await mirrorSystem(await readSystem());
      notices.push({ kind: "error", text: `Your DNS was not restored: ${m}` });
      return false;
    }
  };

  const point = async (): Promise<boolean> => {
    if (!running() || !checks.has(DNS_SWITCH)) {
      await mirrorSystem(get().system);
      notices.push({ kind: "error", text: "Turn DNS filtering on and let its self check pass before pointing Windows at it." });
      return false;
    }
    set({ busy: "point" });
    try {
      const system = await dns.pointSystem();
      set({ system, busy: null, error: null });
      recordSystemCheck(system);
      await mirrorSystem(system);
      notices.push({ kind: "success", text: "Windows now uses Sieve for DNS. Ads and trackers are blocked for every app on this computer." });
      return true;
    } catch (e) {
      const m = message(e);
      set({ busy: null, error: `Windows was not pointed at Sieve: ${m}` });
      await mirrorSystem(await readSystem());
      notices.push({ kind: "error", text: `Windows was not pointed at Sieve: ${m}` });
      return false;
    }
  };

  const turnOff = async () => {
    if (mustAskBeforeQuit(get().system)) {
      // Restore first: a stopped filter with Windows still pointed here resolves nothing.
      if (!(await restore())) {
        await settings.set(DNS_SWITCH, true);
        notices.push({ kind: "error", text: "DNS filtering stays on: Windows still uses Sieve for DNS until it is restored." });
        return;
      }
    }
    set({ busy: "stop" });
    try {
      set({ status: await dns.stop(), check: null, error: null });
    } catch (e) {
      set({ error: message(e) });
    }
    stopPolling();
    set({ busy: null });
    checks.delete(DNS_SWITCH);
    checks.delete(SYSTEM_DNS_SWITCH);
  };

  /**
   * Bring the filter and Windows in line with the switches, one step per
   * round. Every failing step sets its switch back to what is true, so the
   * next round finds nothing to do; MAX_ROUNDS is the backstop.
   */
  const reconcile = async (): Promise<void> => {
    for (let round = 0; round < MAX_ROUNDS; round++) {
      if (disposed || !loaded) return;
      const wantDns = settings.get(DNS_SWITCH);
      const wantSystem = settings.get(SYSTEM_DNS_SWITCH);
      const wantPass = !settings.get(GLOBAL_SWITCH);
      const system = get().system;
      // Windows DNS never read: nothing to compare the system switch with.
      const pointed = system === null ? wantSystem : system.pointed;
      if (wantDns && !running()) await turnOn(false);
      else if (!wantDns && running()) await turnOff();
      // Global Sieving off: running, but blocking nothing. A failed change stops here (no retry loop).
      else if (running() && get().status?.pass_through !== wantPass) {
        if (!(await passThrough(wantPass))) return;
      }
      // Windows changed by itself: the switch follows, nothing is run.
      else if (wantSystem !== pointed && wantSystem === mirrored) await mirrorSystem(system);
      // The user flipped the switch: that is the order.
      else if (wantSystem !== pointed) await (wantSystem ? point() : restore());
      else return;
    }
  };

  const load = async () => {
    await settings.ready;
    if (disposed) return;
    await Promise.all([readStatus(), readAdguard()]);
    const system = await readSystem();
    if (disposed) return;
    // Whatever the switch says from last time, it now says what Windows does.
    await mirrorSystem(system);
    if (needsProxyAtStart(system) && !running()) {
      const r = await turnOn(true);
      if (r.started) {
        notices.push({ kind: "info", text: "Windows uses Sieve for DNS, so Sieve started its DNS filter." });
        if (!settings.get(DNS_SWITCH)) await settings.set(DNS_SWITCH, true);
      } else {
        banner = notices.push({
          kind: "error",
          surface: "banner",
          text: `Windows uses Sieve for DNS, but Sieve's DNS filter could not start (${r.error}). Nothing resolves until you restore your DNS.`,
          action: { label: "Restore my DNS", run: () => void serial(restore) },
        });
      }
    }
    if (running()) schedulePoll();
    loaded = true;
    await reconcile();
  };

  const exit = d.exit;

  return {
    bind() {
      disposed = false;
      const unsubscribe = settings.subscribe(requestReconcile);
      void serial(load);
      return () => {
        disposed = true;
        unsubscribe();
        stopPolling();
      };
    },
    point: () => serial(point),
    restore: () => serial(restore),
    holdClose: () => exit !== null && mustAskBeforeQuit(get().system),
    requestQuit() {
      if (exit === null) return;
      if (mustAskBeforeQuit(get().system)) set({ quitAsked: true });
      else void exit();
    },
    cancelQuit: () => set({ quitAsked: false }),
    quit: (how) =>
      serial(async () => {
        if (exit === null) return;
        if (how === "restore" && !(await restore())) {
          // Not restored: leaving now would leave Windows asking a server that is gone.
          set({ quitAsked: false });
          return;
        }
        set({ quitAsked: false });
        await exit();
      }),
  };
}
