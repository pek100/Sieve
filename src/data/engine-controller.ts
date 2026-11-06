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
 *   turned off, the filter list selection, the domain lists, the user's rules
 *   and exclusions. Whenever the engine answers with anything different, order
 *   aside, the whole policy is sent with the next revision (`setPolicy`): a
 *   part-filled one would clear the rest. The switch defaults off, so the engine
 *   routes nothing until the user turns it on. Nothing is sent while the engine
 *   cannot take a policy (`engineTakesPolicy`); the stored values then wait
 *   untouched. A policy that is over the engine's limit or is refused gives way to
 *   one with the rules as the engine holds them (`policyParts`), so the off
 *   switches always arrive. What was refused is retried at the next probe, not at once;
 * - the encrypted DNS resolvers follow `filtering.upstreams` the same way, with
 *   their own revision, read back once per probe. Their order is the order they
 *   are tried in, so it counts;
 * - the root certificate, only when the user asks (`installRoot`). Its facts
 *   are read after each probe while the engine can answer, and cleared when
 *   it cannot;
 * - AdGuard's service, stopped or started only when the user clicks the
 *   pause offer (`stopAdguard`, `startAdguard`; Windows asks the user first).
 *
 * The passed live check of ENGINE_SWITCH is recorded while the engine
 * reports routing, and forgotten when it stops. A crash loop pushes one Home
 * banner, dismissed when it is over; so does an update on offer or rolled back.
 * Update state rides the probe: there is no separate poll.
 */
import type { PassedChecks } from "@/core/checks";
import { ENGINE_POLL_MS, ENGINE_SWITCH, HTTPS_SWITCH, engineRoutes, engineStatus, enginePhase, engineTakesPolicy, engineUpdate, updateBanner, type EngineSlice } from "@/core/engine";
import type { NoticeBus } from "@/core/notices";
import { selectedListIds } from "@/core/filter-lists";
import { GLOBAL_SWITCH, offKeys } from "@/core/policy";
import { MAX_POLICY_BYTES, type SettingKey } from "@/core/settings/registry";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { FilterListSource } from "./filter-lists-source";
import type { Clock } from "./poller";
import type { EngineDomainList, EnginePolicy, FilterCatalogue } from "./protocol";
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
  /** The update button: `RequestUpdate`, whose meaning the engine decides. */
  requestUpdate(): Promise<void>;
}

export interface EngineControllerDeps {
  engine: EngineSource;
  store: SieveStore;
  clock: Clock;
  settings: SettingsStore;
  checks: PassedChecks;
  notices: NoticeBus;
  /** The catalogue, which turns the stored differences into the lists selected. */
  filterLists: Pick<FilterListSource, "catalogue">;
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

/**
 * The policy the settings ask for. An untouched selection is null, the
 * catalogue's defaults, with no catalogue needed. A changed one needs the
 * catalogue to name its lists; until it is read the engine keeps the selection
 * it has (`heldLists`), so a missing read cannot turn a list on or off.
 */
function wantedPolicy(settings: SettingsStore, catalogue: Pick<FilterCatalogue, "lists"> | null, heldLists: string[] | null): WantedPolicy {
  const selection = settings.get("filters.lists");
  const untouched = Object.keys(selection).length === 0;
  return {
    engine: Boolean(settings.get(SWITCH)),
    sieving: Boolean(settings.get(GLOBAL_SWITCH)),
    off_apps: [...offKeys(settings.get("apps.levels"))],
    https: Boolean(settings.get(HTTPS)),
    lists: untouched ? null : catalogue ? selectedListIds(selection, catalogue) : heldLists,
    domain_lists: [...domainList("block", settings.get("filtering.blockedDomains")), ...domainList("allow", settings.get("filtering.allowedDomains"))],
    user_rules: [...settings.get("filtering.userRules")],
    exclusions: [...settings.get("filtering.exclusions")],
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
    user_rules: sorted(p.user_rules),
    exclusions: sorted(p.exclusions),
  });
}

const rulesAsHeld = (want: WantedPolicy, held: WantedPolicy): WantedPolicy => ({ ...want, domain_lists: held.domain_lists, user_rules: held.user_rules, exclusions: held.exclusions });

/**
 * What to try, in order, so that a refused policy still delivers its switches:
 * all of it; then the rules left as the engine holds them, which it took once and
 * need no compiling; then the off-apps and the list selection too, for a stored
 * value the settings' budgets never saw. Turning something off never waits on
 * the size of what is switched.
 */
function policyParts(want: WantedPolicy, held: WantedPolicy): WantedPolicy[] {
  const switches = rulesAsHeld(want, held);
  return [want, switches, { ...switches, off_apps: held.off_apps, lists: held.lists }];
}

export function createEngineController({ engine, store, clock, settings, checks, notices, filterLists }: EngineControllerDeps): EngineController {
  let disposed = true;
  let policyInFlight = false;
  // The error on show is about the policy, so it ends when the engine holds what is wanted.
  let policyHeldBack = false;
  let upstreamsInFlight = false;
  let catalogue: Pick<FilterCatalogue, "lists"> | null = null;
  let catalogueInFlight = false;
  // The switch is read only after the settings loaded: before that it reads as its default (off).
  let settingsReady = false;
  let banner: number | null = null;
  let update: { id: number; text: string } | null = null;
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
    const text = updateBanner(engineUpdate(e));
    if (text !== (update?.text ?? null)) {
      if (update !== null) notices.dismiss(update.id);
      update = text === null ? null : { id: notices.push({ kind: "info", surface: "banner", text }), text };
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
    if (catalogue === null && Object.keys(settings.get("filters.lists")).length > 0) void readCatalogue();
    const want = wantedPolicy(settings, catalogue, status.policy.lists);
    if (normalised(status.policy) === normalised(want)) {
      if (policyHeldBack) set({ actionError: null });
      policyHeldBack = false;
      return;
    }
    policyInFlight = true;
    const revision = status.policy.revision + 1;
    const tried = new Set([normalised(status.policy)]);
    let holds: WantedPolicy = status.policy;
    let sent = false;
    let refusal: string | null = null;
    try {
      for (const part of policyParts(want, status.policy)) {
        const form = normalised(part);
        if (tried.has(form)) continue;
        tried.add(form);
        const size = new TextEncoder().encode(JSON.stringify({ ...part, revision })).length;
        if (size > MAX_POLICY_BYTES) {
          // Measured here, not sent: the answer could only be a refusal, and the engine's own limit is this one.
          refusal ??= `a policy of ${size} bytes is over the ${MAX_POLICY_BYTES} byte limit`;
          continue;
        }
        try {
          const next = await engine.setPolicy({ ...part, revision });
          const probe = get().probe;
          if (probe?.pipe?.kind === "welcome") set({ probe: { ...probe, pipe: { ...probe.pipe, status: next } } });
          holds = part;
          sent = true;
          break;
        } catch (e) {
          refusal ??= message(e);
        }
      }
    } finally {
      policyInFlight = false;
    }
    policyHeldBack = refusal !== null;
    if (refusal === null) set({ actionError: null });
    else if (normalised(rulesAsHeld(want, holds)) === normalised(holds)) set({ actionError: `Could not tell the engine your rules: ${refusal}. Your switches reached it, and it keeps the rules it had.` });
    else set({ actionError: `Could not tell the engine: ${refusal}` });
    // Only a send that went through follows: after a refusal, following now would send it again at once, forever.
    if (sent && !disposed) follow();
  };

  // Once it is read it stays: the catalogue is compiled into this build. A failed
  // read tries again at the next probe, and the engine keeps what it has meanwhile.
  const readCatalogue = async () => {
    if (catalogueInFlight) return;
    catalogueInFlight = true;
    try {
      catalogue = await filterLists.catalogue();
    } catch {
      catalogue = null;
    } finally {
      catalogueInFlight = false;
    }
    if (catalogue !== null) void syncPolicy();
  };

  // Compared with what the engine holds on every probe, so a list the engine lost
  // or never had is sent again. The setting is never empty (the registry refuses
  // that, as the engine does), so there is always a list to compare.
  const syncUpstreams = async () => {
    if (disposed || !settingsReady || upstreamsInFlight || !engineTakesPolicy(get())) return;
    upstreamsInFlight = true;
    try {
      const held = await engine.dnsUpstreams();
      const want = settings.get("filtering.upstreams");
      const same = want.length === held.upstreams.length && want.every((u, i) => u === held.upstreams[i]);
      if (!same) await engine.setDnsUpstreams({ revision: held.revision + 1, upstreams: [...want] });
      if (get().dnsError) set({ dnsError: null });
    } catch (e) {
      set({ dnsError: `The DNS servers did not reach the engine: ${message(e)}` });
    } finally {
      upstreamsInFlight = false;
    }
  };

  // Answered at once with the Status; the engine's work then shows through the probe.
  const requestUpdate = async () => {
    if (get().requestingUpdate) return;
    set({ requestingUpdate: true, actionError: null });
    try {
      const next = await engine.requestUpdate();
      const probe = get().probe;
      if (probe?.pipe?.kind === "welcome") set({ probe: { ...probe, pipe: { ...probe.pipe, status: next } } });
    } catch (e) {
      set({ actionError: `The update request did not go through: ${message(e)}` });
    } finally {
      set({ requestingUpdate: false });
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
        await syncUpstreams();
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

      const unSettings = settings.subscribe(() => {
        void syncPolicy();
        void syncUpstreams();
      });
      void settings.ready.then(() => {
        settingsReady = true;
        void syncPolicy();
        void syncUpstreams();
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
        if (update !== null) notices.dismiss(update.id);
        update = null;
      };
    },
    requestUpdate,
    stopAdguard: () => adguard("stopping", () => engine.stopAdguard()),
    startAdguard: () => adguard("starting", () => engine.startAdguard()),
    installRoot,
  };
}
