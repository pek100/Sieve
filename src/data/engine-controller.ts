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
 *   and exclusions, and DNS encryption (`plain_dns` only when the user turned it off). Whenever the engine answers with anything different, order
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
 * - "Try decrypting again", only when the user asks (`tryDecryptAgain`). Self-healing's
 *   notices are read after each probe while the engine holds HTTPS on, and the rows
 *   only when their revision moved. A failed read keeps the rows and says why;
 * - nothing about the apps' problems: they are read after each probe while the
 *   engine routes (`issues`), only when their revision moved, and stay local;
 * - AdGuard's service, stopped or started only when the user clicks the
 *   pause offer (`stopAdguard`, `startAdguard`; Windows asks the user first).
 *
 * The passed live check of ENGINE_SWITCH is recorded while the engine
 * reports routing, and forgotten when it stops. A crash loop pushes one Home
 * banner, dismissed when it is over; so does an update on offer or rolled back,
 * and no encrypted DNS server answering (it points at the switch, never flips it).
 * Update state rides the probe: there is no separate poll.
 */
import type { PassedChecks } from "@/core/checks";
import { CONTENT_SWITCH, DNS_CLIENT_CAPTURE as DNS_CLIENT_CAPTURE_KEY, DNS_ENCRYPTION as DNS_ENCRYPTION_KEY, ENGINE_POLL_MS, ENGINE_SWITCH, HTTPS_SWITCH, engineRoutes, engineStatus, enginePhase, engineVersion, engineTakesPolicy, engineUpdate, httpsInForce, updateBanner, type EngineSlice } from "@/core/engine";
import type { ExclusionsFacts, HealGroup } from "@/core/exclusions";
import type { NoticeBus } from "@/core/notices";
import { selectedListIds } from "@/core/filter-lists";
import { GLOBAL_SWITCH, offKeys } from "@/core/policy";
import { trackingInForce } from "@/core/tracking";
import { MAX_POLICY_BYTES, REGISTRY, type SettingKey } from "@/core/settings/registry";
import type { SieveStore } from "@/core/store";
import type { EngineSource } from "./engine-source";
import type { FilterListSource } from "./filter-lists-source";
import type { Clock } from "./poller";
import { ProtocolError, type EngineDomainList, type EnginePolicy, type ExclusionsPage, type FilterCatalogue } from "./protocol";
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
  /** "Try decrypting again": one row, or with no line one app's rejected sites. */
  tryDecryptAgain(line: string | null, app: string | null, reason: string | null): Promise<void>;
  /** "Try decrypting all again" for an app: every one of its files named. */
  tryDecryptAllAgain(apps: readonly string[]): Promise<void>;
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
const CONTENT = CONTENT_SWITCH as SettingKey;
const DNS_ENCRYPTION = DNS_ENCRYPTION_KEY as SettingKey;
const DNS_CLIENT_CAPTURE = DNS_CLIENT_CAPTURE_KEY as SettingKey;

/**
 * The Home banner while no encrypted DNS server answers (the status's
 * `dns_unreachable`). It points at the switch and never flips it: plain DNS is
 * only ever the user's choice.
 */
export const DNS_UNREACHABLE_BANNER = `No encrypted DNS server answers on this network, so sites may not load. Hotel and airport Wi-Fi often needs plain DNS to show its sign-in page: you can turn off ${REGISTRY[DNS_ENCRYPTION].label} in Settings > Filtering.`;
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));
const captureUnknownError = `This version of Sieve's engine does not know "${REGISTRY[DNS_CLIENT_CAPTURE].label}". Your other settings reached it.`;

/** Notices the window keeps for the toast hook: far more than one person reads, as the engine's own ring. */
const HEAL_KEPT = 64;

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
    content: Boolean(settings.get(CONTENT)),
    // Plain only when the user turned encryption off: an unread setting reads as its default, on.
    plain_dns: settings.get(DNS_ENCRYPTION) === false,
    // Only when off, so an engine from before the field never sees it at the default (on).
    ...(settings.get(DNS_CLIENT_CAPTURE) === false ? { skip_dns_capture: true } : {}),
    lists: untouched ? null : catalogue ? selectedListIds(selection, catalogue) : heldLists,
    domain_lists: [...domainList("block", settings.get("filtering.blockedDomains")), ...domainList("allow", settings.get("filtering.allowedDomains"))],
    user_rules: [...settings.get("filtering.userRules")],
    exclusions: [...settings.get("filtering.exclusions")],
    // Both left out while empty, as the engine writes them, so a policy without them is the one it always was.
    ...nonEmpty("custom_lists", settings.get("filters.custom").map((l) => ({ ...l }))),
    // In force only: an option stored on while HTTPS decryption is off or unavailable is never sent.
    ...nonEmpty("tracking", trackingInForce((k) => settings.get(k))),
  };
}

const nonEmpty = <K extends string, T>(key: K, list: T[]): Partial<Record<K, T[]>> => (list.length > 0 ? ({ [key]: list } as Record<K, T[]>) : {});

/** One form of a policy for comparing: its lists' order means nothing. */
function normalised(p: WantedPolicy): string {
  const sorted = (l: readonly string[]) => [...l].sort();
  return JSON.stringify({
    engine: p.engine,
    https: p.https,
    content: p.content ?? false,
    plain_dns: p.plain_dns ?? false,
    skip_dns_capture: p.skip_dns_capture ?? false,
    sieving: p.sieving,
    off_apps: sorted(p.off_apps),
    lists: p.lists && sorted(p.lists),
    domain_lists: p.domain_lists
      .filter((l) => l.enabled && l.entries.length > 0)
      .map((l) => ({ kind: l.kind, entries: sorted(l.entries) }))
      .sort((a, b) => a.kind.localeCompare(b.kind)),
    user_rules: sorted(p.user_rules),
    exclusions: sorted(p.exclusions),
    // The engine leaves both out while empty.
    custom_lists: [...(p.custom_lists ?? [])].sort((a, b) => a.id.localeCompare(b.id)).map((l) => [l.id, l.title, l.url, l.enabled]),
    tracking: sorted(p.tracking ?? []),
  });
}

const rulesAsHeld = (want: WantedPolicy, held: WantedPolicy): WantedPolicy => ({ ...want, domain_lists: held.domain_lists, user_rules: held.user_rules, exclusions: held.exclusions });

/**
 * What to try, in order, so that a refused policy still delivers its switches:
 * all of it; then the rules left as the engine holds them, which it took once and
 * need no compiling; then the off-apps and the list selection too, for a stored
 * value the settings' budgets never saw. Turning something off never waits on
 * the size of what is switched. Each of those is tried once more with
 * `skip_dns_capture` as the engine holds it: an engine from before that field
 * refuses any policy that names it, and the rest must still arrive.
 */
function policyParts(want: WantedPolicy, held: WantedPolicy): WantedPolicy[] {
  const switches = rulesAsHeld(want, held);
  const parts = [want, switches, { ...switches, off_apps: held.off_apps, lists: held.lists, custom_lists: held.custom_lists ?? [], tracking: held.tracking ?? [] }];
  return [...parts, ...parts.map((p) => captureAsHeld(p, held))];
}

/** `p` with the capture switch as `held` has it, left out while that is the default (on). */
function captureAsHeld(p: WantedPolicy, held: WantedPolicy): WantedPolicy {
  const rest = { ...p };
  delete rest.skip_dns_capture;
  return held.skip_dns_capture ? { ...rest, skip_dns_capture: true } : rest;
}

export function createEngineController({ engine, store, clock, settings, checks, notices, filterLists }: EngineControllerDeps): EngineController {
  let disposed = true;
  let policyInFlight = false;
  // The error on show is about the policy, so it ends when the engine holds what is wanted.
  let policyHeldBack = false;
  // The engine version that refused the capture switch (an engine from before it), so it is not sent again to it.
  let captureRefusedBy: string | null = null;
  let upstreamsInFlight = false;
  let catalogue: Pick<FilterCatalogue, "lists"> | null = null;
  let catalogueInFlight = false;
  // The switch is read only after the settings loaded: before that it reads as its default (off).
  let settingsReady = false;
  let banner: number | null = null;
  let dnsBanner: number | null = null;
  let update: { id: number; text: string } | null = null;
  let probeNow: () => Promise<void> = async () => {};
  // Null until the first read. The engine is a service that outlives this window,
  // so what it did before that read is not news: the rows show it, and no toast does.
  let healCursor: { run: number; after: number } | null = null;

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
    const unreachable = engineStatus(e)?.dns_unreachable === true;
    if (unreachable && dnsBanner === null) dnsBanner = notices.push({ kind: "error", surface: "banner", text: DNS_UNREACHABLE_BANNER });
    if (!unreachable && dnsBanner !== null) {
      notices.dismiss(dnsBanner);
      dnsBanner = null;
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
    const version = engineVersion(e);
    const wanted = wantedPolicy(settings, catalogue, status.policy.lists);
    // This engine refused the capture switch once: it is not sent again until the engine's version changes.
    const captureUnknown = captureRefusedBy !== null && captureRefusedBy === version && (wanted.skip_dns_capture ?? false) !== (status.policy.skip_dns_capture ?? false);
    const want = captureUnknown ? captureAsHeld(wanted, status.policy) : wanted;
    if (normalised(status.policy) === normalised(want)) {
      if (captureUnknown) set({ actionError: captureUnknownError });
      else if (policyHeldBack) set({ actionError: null });
      policyHeldBack = captureUnknown;
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
    policyHeldBack = refusal !== null || captureUnknown;
    // An engine from before the capture switch took everything but it: said, and not sent again to that engine version.
    const captureRefused = sent && refusal !== null && (want.skip_dns_capture ?? false) !== (holds.skip_dns_capture ?? false);
    if (captureRefused) captureRefusedBy = version;
    else if (sent && (holds.skip_dns_capture ?? false) === (wanted.skip_dns_capture ?? false)) captureRefusedBy = null;
    if (captureRefused || (captureUnknown && refusal === null)) set({ actionError: captureUnknownError });
    else if (refusal === null) set({ actionError: null });
    else if (normalised(rulesAsHeld(want, holds)) === normalised(holds)) set({ actionError: `Could not tell the engine your rules: ${refusal}. Your switches reached it, and it keeps the rules it had.` });
    else set({ actionError: `Could not tell the engine: ${refusal}` });
    // Only a send that went through follows: after a refusal, following now would send it again at once, forever.
    // Nor after the capture switch was left out: the next follow would send it again at once.
    if (sent && !captureRefused && !disposed) follow();
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
  // that, as the engine does), so there is always a list to compare. What it said it
  // holds stays in the slice for the row to read back, null while it cannot be asked.
  const keepHeld = (held: readonly string[] | null) => {
    if (JSON.stringify(get().heldUpstreams ?? null) !== JSON.stringify(held)) set({ heldUpstreams: held });
  };
  const syncUpstreams = async () => {
    if (disposed || !settingsReady || upstreamsInFlight) return;
    if (!engineTakesPolicy(get())) return keepHeld(null);
    upstreamsInFlight = true;
    try {
      const held = await engine.dnsUpstreams();
      const want = settings.get("filtering.upstreams");
      const same = want.length === held.upstreams.length && want.every((u, i) => u === held.upstreams[i]);
      keepHeld(held.upstreams);
      if (!same) keepHeld((await engine.setDnsUpstreams({ revision: held.revision + 1, upstreams: [...want] })).upstreams);
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

  // The rest of the rows after `first`. The revision of the first page is the one
  // kept, so a change during the walk shows at the next probe as a moved revision.
  const walkRows = async (first: ExclusionsPage): Promise<ExclusionsFacts> => {
    const rows = [...first.rows];
    let skipped = first.skipped;
    let next = first.next;
    while (next !== null) {
      const page = await engine.exclusions(next);
      if (page.next !== null && page.next <= next) throw new ProtocolError("exclusions.next does not move on");
      rows.push(...page.rows);
      skipped += page.skipped;
      next = page.next;
    }
    return { revision: first.revision, rows, scope: first.scope, browsers: first.browsers, skipped };
  };

  // Cheap, so per probe; the rows are read only when their revision moved. A new
  // engine run starts its revisions and ids over, so a cursor or a revision means
  // nothing outside its run: everything the new run holds is read from the start, and
  // told, and rows the read cannot replace go, being the old run's.
  const readHeal = async () => {
    if (!httpsInForce(get())) {
      if (get().exclusions || get().exclusionsError || (get().healNotices?.length ?? 0) > 0) set({ exclusions: null, exclusionsError: null, healNotices: [] });
      return;
    }
    let newRun = false;
    try {
      const baseline = healCursor === null;
      let answer = await engine.healNotices(healCursor?.after ?? 0);
      if (healCursor !== null && answer.run !== healCursor.run) answer = await engine.healNotices(0);
      const { run } = answer;
      newRun = healCursor?.run !== run;
      healCursor = { run, after: answer.revision };
      if (!baseline && answer.notices.length > 0) {
        const fresh: HealGroup[] = answer.notices.map((n) => ({ ...n, key: `${run}:${n.id}` }));
        const kept = (get().healNotices ?? []).filter((g) => !fresh.some((n) => n.key === g.key));
        set({ healNotices: [...kept, ...fresh].slice(-HEAL_KEPT) });
      }
      const held = get().exclusions;
      const rows = !newRun && held && held.revision === answer.exclusions_revision ? held : await walkRows(await engine.exclusions(0));
      set({ exclusions: rows, exclusionsError: null });
    } catch (e) {
      set(newRun ? { exclusions: null, exclusionsError: message(e) } : { exclusionsError: message(e) });
    }
  };

  // Per probe while the engine routes: the apps only come when they changed, and
  // a new run starts its revisions over, so its answer is read from the start. A
  // failed read keeps the apps and says why; not routing clears them (the
  // engine sees no traffic, so there is nothing true to show).
  const readIssues = async () => {
    if (!engineRoutes(get())) {
      if (get().issues || get().issuesError) set({ issues: null, issuesError: null });
      return;
    }
    try {
      const held = get().issues ?? null;
      let answer = await engine.issues(held?.revision ?? 0);
      if (held && answer.run !== held.run) answer = await engine.issues(0);
      if (held && answer.run === held.run && answer.revision === held.revision) {
        if (get().issuesError) set({ issuesError: null });
        return;
      }
      set({ issues: answer, issuesError: null });
    } catch (e) {
      set({ issuesError: message(e) });
    }
  };

  const tryDecryptAgain = async (line: string | null, app: string | null, reason: string | null) => {
    set({ exclusionsActionError: null });
    try {
      set({ exclusions: await walkRows(await engine.tryDecryptAgain(line, app, reason)) });
    } catch (e) {
      set({ exclusionsActionError: `Sieve could not try that again: ${message(e)}` });
    }
  };

  // One error for the whole try: a later success must not wipe an earlier refusal.
  // Stops there, and each answer's rows show what was taken back so far.
  const tryDecryptAllAgain = async (apps: readonly string[]) => {
    set({ exclusionsActionError: null });
    try {
      for (const app of apps) set({ exclusions: await walkRows(await engine.tryDecryptAgain(null, app, null)) });
    } catch (e) {
      set({ exclusionsActionError: `Sieve could not try that again: ${message(e)}` });
    }
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
        await readHeal();
        await readIssues();
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
        if (dnsBanner !== null) notices.dismiss(dnsBanner);
        dnsBanner = null;
        if (update !== null) notices.dismiss(update.id);
        update = null;
      };
    },
    requestUpdate,
    stopAdguard: () => adguard("stopping", () => engine.stopAdguard()),
    startAdguard: () => adguard("starting", () => engine.startAdguard()),
    installRoot,
    tryDecryptAgain,
    tryDecryptAllAgain,
  };
}
