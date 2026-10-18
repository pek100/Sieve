/**
 * The engine controller: the one owner of the store's `engine` part and the
 * only caller of the engine source. It asks at load and then every
 * ENGINE_POLL_MS (plan 1.6.5), one probe at a time; a probe that fails
 * clears the facts and records why, so nothing is ever shown from a stale
 * or assumed state. Time comes from the injected clock.
 *
 * What it changes, and only these:
 * - the engine's policy follows the user's switch `filtering.engine`
 *   (ENGINE_SWITCH): whenever the engine answers with a different value, the
 *   switch is sent with the next revision (`setPolicy`). The switch defaults
 *   off, so the engine routes nothing until the user turns it on;
 * - AdGuard's service, stopped or started only when the user clicks the
 *   pause offer (`stopAdguard`, `startAdguard`; Windows asks the user first).
 *
 * The passed live check of ENGINE_SWITCH is recorded while the engine
 * reports routing, and forgotten when it stops. A crash loop pushes one Home
 * banner, dismissed when it is over.
 */
import type { PassedChecks } from "@/core/checks";
import { ENGINE_POLL_MS, ENGINE_SWITCH, engineStatus, enginePhase, type EngineSlice } from "@/core/engine";
import type { NoticeBus } from "@/core/notices";
import type { SettingKey } from "@/core/settings/registry";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";
import type { SettingsStore } from "./settings-store";

export interface EngineController {
  /** Probe now and on the cadence, and follow the switch. Returns the undo. */
  bind(): () => void;
  /** The pause offer: stop AdGuard's service (Windows asks the user), then probe. */
  stopAdguard(): Promise<void>;
  /** Start AdGuard's service again (Windows asks the user), then probe. */
  startAdguard(): Promise<void>;
}

export interface EngineControllerDeps {
  engine: EngineSource;
  store: SieveStore;
  clock: Clock;
  settings: SettingsStore;
  checks: PassedChecks;
  notices: NoticeBus;
}

/** The Home banner of a crash loop (plan 1.6.4). Never says blocked or filtering: nothing was. */
export const CRASH_LOOP_BANNER =
  "Sieve's engine stopped routing after repeated failures. Your network works as usual. Details in Settings > Filtering.";

const SWITCH = ENGINE_SWITCH as SettingKey;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function createEngineController({ engine, store, clock, settings, checks, notices }: EngineControllerDeps): EngineController {
  let disposed = true;
  let policyInFlight = false;
  // The switch is read only after the settings loaded: before that it reads as its default (off).
  let settingsReady = false;
  let banner: number | null = null;
  let probeNow: () => Promise<void> = async () => {};

  const get = () => store.getState().engine;
  const set = (patch: Partial<EngineSlice>) => {
    if (!disposed) store.setEngine({ ...get(), ...patch });
  };

  // Facts in, consequences out: passed check, banner, policy.
  const follow = () => {
    const e = get();
    const phase = enginePhase(e);
    if (phase === "routing") checks.add(ENGINE_SWITCH);
    else checks.delete(ENGINE_SWITCH);
    if (phase === "crash_loop" && banner === null) banner = notices.push({ kind: "error", surface: "banner", text: CRASH_LOOP_BANNER });
    if (phase !== "crash_loop" && banner !== null) {
      notices.dismiss(banner);
      banner = null;
    }
    void syncPolicy();
  };

  const syncPolicy = async () => {
    const status = engineStatus(get());
    if (disposed || !settingsReady || policyInFlight || status === null) return;
    const want = Boolean(settings.get(SWITCH));
    if (status.policy.engine === want) return;
    policyInFlight = true;
    try {
      const next = await engine.setPolicy({ revision: status.policy.revision + 1, engine: want });
      const probe = get().probe;
      if (probe?.pipe?.kind === "welcome") set({ probe: { ...probe, pipe: { ...probe.pipe, status: next } }, actionError: null });
    } catch (e) {
      set({ actionError: `Could not tell the engine: ${message(e)}` });
    } finally {
      policyInFlight = false;
    }
    if (!disposed) follow();
  };

  const adguard = async (action: "stopping" | "starting", run: () => Promise<void>) => {
    if (get().adguard) return;
    set({ adguard: action, actionError: null });
    try {
      await run();
    } catch (e) {
      set({ actionError: `${action === "stopping" ? "AdGuard was not paused" : "AdGuard was not started"}: ${message(e)}` });
    } finally {
      set({ adguard: null });
    }
    await probeNow();
  };

  return {
    bind() {
      disposed = false;
      let timer: unknown = null;

      const probe = async () => {
        try {
          const facts = await engine.probe();
          set({ probe: facts, error: null });
        } catch (e) {
          set({ probe: null, error: message(e) });
        }
        if (!disposed) follow();
      };
      probeNow = probe;

      // The next probe is scheduled only after the previous one settled.
      const cycle = async () => {
        await probe();
        if (disposed) return;
        timer = clock.setTimeout(() => {
          timer = null;
          void cycle();
        }, ENGINE_POLL_MS);
      };

      const unSettings = settings.subscribe(() => void syncPolicy());
      void settings.ready.then(() => {
        settingsReady = true;
        void syncPolicy();
      });
      void cycle();
      return () => {
        disposed = true;
        unSettings();
        if (timer !== null) clock.clearTimeout(timer);
        timer = null;
        probeNow = async () => {};
        if (banner !== null) notices.dismiss(banner);
        banner = null;
      };
    },
    stopAdguard: () => adguard("stopping", () => engine.stopAdguard()),
    startAdguard: () => adguard("starting", () => engine.startAdguard()),
  };
}
