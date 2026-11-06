/**
 * The engine controller: the one owner of the store's `engine` part and the
 * only caller of `probe`, `setPolicy` and the AdGuard actions. It asks at load and then every
 * ENGINE_POLL_MS (plan 1.6.5), one probe at a time; a probe that fails
 * clears the facts and records why, so nothing is ever shown from a stale
 * or assumed state. Time comes from the injected clock.
 *
 * What it changes, and only these:
 * - the engine's policy follows the user's settings: the switch
 *   `filtering.engine` (ENGINE_SWITCH), the global Sieving switch, the apps
 *   turned off and the domain lists. Whenever the engine answers with anything
 *   different, order aside, the whole policy is sent with the next revision
 *   (`setPolicy`): a part-filled one would clear the rest. The switch defaults
 *   off, so the engine routes nothing until the user turns it on. Nothing is
 *   sent while the engine cannot take a policy (`engineTakesPolicy`); the
 *   stored values then wait untouched. A refused send is retried at the next
 *   probe, not at once;
 * - the root certificate, only when the user asks (`installRoot`). Its facts
 *   are read after each probe while the engine can answer, and cleared when
 *   it cannot;
 * - AdGuard's service, stopped or started only when the user clicks the
 *   pause offer (`stopAdguard`, `startAdguard`; Windows asks the user first).
 *
 * The passed live check of ENGINE_SWITCH is recorded while the engine
 * reports routing, and forgotten when it stops. A crash loop pushes one Home
 * banner, dismissed when it is over.
 */
import type { PassedChecks } from "@/core/checks";
import { ENGINE_POLL_MS, ENGINE_SWITCH, HTTPS_SWITCH, engineRoutes, engineStatus, enginePhase, engineTakesPolicy, type EngineSlice } from "@/core/engine";
import type { NoticeBus } from "@/core/notices";
import { GLOBAL_SWITCH, offKeys } from "@/core/policy";
import type { SettingKey } from "@/core/settings/registry";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { Clock } from "./poller";
import type { EngineDomainList, EnginePolicy } from "./protocol";
import type { SettingsStore } from "./settings-store";

export interface EngineController {
  /** Probe now and on the cadence, and follow the switch. Returns the undo. */
  bind(): () => void;
  /** The pause offer: stop AdGuard's service (Windows asks the user), then probe. */
  stopAdguard(): Promise<void>;
  /** Start AdGuard's service again (Windows asks the user), then probe. */
  startAdguard(): Promise<void>;
  /** The user's Reinstall: a new root and key, then probe. */
  installRoot(): Promise<void>;
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
const HTTPS = HTTPS_SWITCH as SettingKey;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

type WantedPolicy = Omit<EnginePolicy, "revision">;

function domainList(kind: EngineDomainList["kind"], entries: readonly string[]): EngineDomainList[] {
  return entries.length > 0 ? [{ kind, entries: [...entries], enabled: true }] : [];
}

/** The policy the settings ask for. List selection belongs to Settings' list view; null keeps the catalogue's defaults. */
function wantedPolicy(settings: SettingsStore): WantedPolicy {
  return {
    engine: Boolean(settings.get(SWITCH)),
    sieving: Boolean(settings.get(GLOBAL_SWITCH)),
    off_apps: [...offKeys(settings.get("apps.levels"))],
    https: Boolean(settings.get(HTTPS)),
    lists: null,
    domain_lists: [...domainList("block", settings.get("filtering.blockedDomains")), ...domainList("allow", settings.get("filtering.allowedDomains"))],
  };
}

/** One form of a policy for comparing: its lists' order means nothing. */
function normalised(p: WantedPolicy): string {
  const sorted = (l: readonly string[]) => [...l].sort();
  return JSON.stringify({
    engine: p.engine,
    https: p.https,
    sieving: p.sieving,
    off_apps: sorted(p.off_apps),
    lists: p.lists && sorted(p.lists),
    domain_lists: p.domain_lists
      .filter((l) => l.enabled && l.entries.length > 0)
      .map((l) => ({ kind: l.kind, entries: sorted(l.entries) }))
      .sort((a, b) => a.kind.localeCompare(b.kind)),
  });
}

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
    if (engineRoutes(e)) checks.add(ENGINE_SWITCH);
    else checks.delete(ENGINE_SWITCH);
    if (phase === "crash_loop" && banner === null) banner = notices.push({ kind: "error", surface: "banner", text: CRASH_LOOP_BANNER });
    if (phase !== "crash_loop" && banner !== null) {
      notices.dismiss(banner);
      banner = null;
    }
    void syncPolicy();
  };

  // Sent only while the engine can take a policy (engineTakesPolicy, the same
  // fact that locks the switch in Settings). Before that a stored value, an
  // old file's included, is left as it is and nothing claims it is in force:
  // the row shows the engine's own value.
  const syncPolicy = async () => {
    const e = get();
    const status = engineStatus(e);
    if (disposed || !settingsReady || policyInFlight || !engineTakesPolicy(e) || status === null) return;
    const want = wantedPolicy(settings);
    if (normalised(status.policy) === normalised(want)) return;
    policyInFlight = true;
    let sent = false;
    try {
      const next = await engine.setPolicy({ ...want, revision: status.policy.revision + 1 });
      const probe = get().probe;
      if (probe?.pipe?.kind === "welcome") set({ probe: { ...probe, pipe: { ...probe.pipe, status: next } }, actionError: null });
      sent = true;
    } catch (e) {
      set({ actionError: `Could not tell the engine: ${message(e)}` });
    } finally {
      policyInFlight = false;
    }
    // A refusal waits for the next probe: following now would send it again at once, forever.
    if (sent && !disposed) follow();
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

  // One read per probe, only while the engine can answer (the same fact as a
  // policy). A failed read clears the facts: nothing shows from a stale state.
  const readCert = async () => {
    if (!engineTakesPolicy(get())) {
      if (get().cert || get().certError) set({ cert: null, certError: null });
      return;
    }
    try {
      set({ cert: await engine.certStatus(), certError: null });
    } catch (e) {
      set({ cert: null, certError: message(e) });
    }
  };

  const installRoot = async () => {
    set({ certActionError: null });
    try {
      set({ cert: await engine.installRoot() });
    } catch (e) {
      set({ certActionError: `The certificate was not reinstalled: ${message(e)}` });
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
        if (disposed) return;
        follow();
        await readCert();
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
    installRoot,
  };
}
