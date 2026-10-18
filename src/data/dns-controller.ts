/**
 * The DNS controller: the one owner of DNS state (the store's `dns` part)
 * and the only caller of the DNS source. It follows two switches:
 *
 * - `filtering.dns` (DNS_SWITCH). On: dns_start, then dns_self_check; a
 *   passed check is recorded in passedChecks. A failed start (port 53 busy)
 *   or a failed check turns the switch back off with a notice naming the
 *   error. Off: dns_stop.
 * - the global Sieving switch (GLOBAL_SWITCH). Off puts a running filter in
 *   pass-through (dns_set_pass_through): it keeps answering and forwards
 *   everything; on filters again. The filter is never stopped for it.
 *
 * Sieve never changes Windows DNS (docs/conventions.md, "Sieve off means a
 * normal network"). The safety net only reads it: at load and every
 * WINDOWS_DNS_POLL_MS, `windows_dns` is read, and while `strandedAdapters`
 * finds an adapter asking 127.0.0.1 or ::1 with no Sieve listener there
 * (an old build pointed it, or someone did by hand), a Home banner says so
 * (STRANDED_DNS_TEXT), with no action: it points to Windows network
 * settings. It goes when that stops being true; the DNS card says the same
 * for as long as it is true.
 *
 * While `filtering.dns` is unavailable (registry `unavailableUntil`) it reads
 * off whatever is stored, so the filter is never started; the safety net runs
 * all the same.
 *
 * dns_status is read every DNS_POLL_MS while the filter runs, with the
 * AdGuard read alongside. Time comes from the injected clock.
 */
import type { PassedChecks } from "@/core/checks";
import {
  DNS_POLL_MS,
  DNS_SWITCH,
  STRANDED_DNS_TEXT,
  UPSTREAMS_KEY,
  WINDOWS_DNS_POLL_MS,
  CHECK_DETAILS_AT,
  checkFailedLine,
  checkFailure,
  strandedAdapters,
  type DnsSlice,
} from "@/core/dns";
import type { NoticeBus } from "@/core/notices";
import { GLOBAL_SWITCH } from "@/core/policy";
import type { SieveStore } from "@/core/store";
import type { DnsSource } from "./dns-source";
import type { Clock } from "./poller";
import type { SelfCheck } from "./protocol";
import type { SettingsStore } from "./settings-store";

export interface DnsController {
  /** Load, follow the switches, poll, and keep the safety net. Returns the undo. */
  bind(): () => void;
}

export interface DnsControllerDeps {
  dns: DnsSource;
  store: SieveStore;
  settings: SettingsStore;
  notices: NoticeBus;
  checks: PassedChecks;
  clock: Clock;
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
  let windowsTimer: unknown = null;
  /** The safety banner on screen (its notice id), if any. */
  let safetyBanner: number | null = null;

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

  /**
   * Show or clear the safety banner from the newest facts. Not while an
   * action is in flight (a filter being started is not "not running"), and
   * not before the first load (nothing is known yet). A banner the user
   * dismissed comes back only after the problem went away and returned.
   */
  const updateSafety = () => {
    if (disposed || !loaded || get().busy !== null) return;
    const stranded = strandedAdapters(get().windows, get().status).length > 0;
    if (stranded && safetyBanner === null) {
      // No action: the way out is Windows' own network settings, which the text names.
      safetyBanner = notices.push({ kind: "error", surface: "banner", text: STRANDED_DNS_TEXT });
    } else if (!stranded && safetyBanner !== null) {
      notices.dismiss(safetyBanner);
      safetyBanner = null;
    }
  };

  const readWindows = async () => {
    try {
      set({ windows: await dns.windowsDns() });
    } catch {
      // Read only and for a warning: a failed read keeps the last reading
      // (unknown is not "nothing points at Sieve").
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
        await Promise.all([readStatus(), readAdguard()]);
        if (disposed) return;
        if (running()) schedulePoll();
        // The filter stopped by itself: its check no longer stands.
        else checks.delete(DNS_SWITCH);
        requestReconcile();
      });
    }, DNS_POLL_MS);
  };

  /** The safety net's read, from load on, whether or not the filter runs. */
  const scheduleWindowsPoll = () => {
    if (disposed || windowsTimer !== null) return;
    windowsTimer = clock.setTimeout(() => {
      windowsTimer = null;
      void serial(async () => {
        if (disposed) return;
        await readWindows();
        updateSafety();
        scheduleWindowsPoll();
      });
    }, WINDOWS_DNS_POLL_MS);
  };

  const failedCheck = (e: unknown): SelfCheck => ({
    pass: false,
    checks: [{ kind: "call", server: "", name: "", expect: "an answer from the filter", got: message(e), pass: false }],
  });

  /** Start and self check; on any failure the switch goes back off with a notice. */
  const turnOn = async (): Promise<void> => {
    set({ busy: "start", error: null, check: null });
    try {
      set({ status: await dns.start({ upstreams: settings.get(UPSTREAMS_KEY) }) });
    } catch (e) {
      const m = message(e);
      set({ busy: null, error: m });
      await settings.set(DNS_SWITCH, false);
      notices.push({ kind: "error", text: `DNS filtering could not start: ${m}` });
      return;
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
      notices.push({ kind: "success", text: "DNS filtering is on for lookups sent to 127.0.0.1:53." });
      return;
    }
    // Short and plain in the toast and the card; the technical replies stay
    // in the card's self check details (checkDetails).
    set({ busy: "stop" });
    try {
      set({ status: await dns.stop() });
    } catch (e) {
      set({ error: message(e) });
    }
    stopPolling();
    set({ busy: null, error: checkFailedLine(check) });
    await settings.set(DNS_SWITCH, false);
    notices.push({ kind: "error", text: `DNS filtering could not start: its self check failed ${checkFailure(check)}. Details in ${CHECK_DETAILS_AT}.` });
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

  const turnOff = async () => {
    set({ busy: "stop" });
    try {
      set({ status: await dns.stop(), check: null, error: null });
    } catch (e) {
      set({ error: message(e) });
    }
    stopPolling();
    set({ busy: null });
    checks.delete(DNS_SWITCH);
  };

  /**
   * Bring the filter in line with the switches, one step per round. Every
   * failing step sets its switch back to what is true, so the next round
   * finds nothing to do; MAX_ROUNDS is the backstop. Then the safety net
   * looks at the result.
   */
  const reconcile = async (): Promise<void> => {
    for (let round = 0; round < MAX_ROUNDS; round++) {
      if (disposed || !loaded) return;
      const wantDns = settings.get(DNS_SWITCH);
      const wantPass = !settings.get(GLOBAL_SWITCH);
      if (wantDns && !running()) await turnOn();
      else if (!wantDns && running()) await turnOff();
      // Global Sieving off: running, but blocking nothing. A failed change stops here (no retry loop).
      else if (running() && get().status?.pass_through !== wantPass) {
        if (!(await passThrough(wantPass))) break;
      } else break;
    }
    updateSafety();
  };

  const load = async () => {
    await settings.ready;
    if (disposed) return;
    await Promise.all([readStatus(), readAdguard(), readWindows()]);
    if (disposed) return;
    if (running()) schedulePoll();
    loaded = true;
    await reconcile();
    scheduleWindowsPoll();
  };

  return {
    bind() {
      disposed = false;
      const unsubscribe = settings.subscribe(requestReconcile);
      void serial(load);
      return () => {
        disposed = true;
        unsubscribe();
        stopPolling();
        if (windowsTimer !== null) clock.clearTimeout(windowsTimer);
        windowsTimer = null;
        if (safetyBanner !== null) notices.dismiss(safetyBanner);
        safetyBanner = null;
      };
    },
  };
}
