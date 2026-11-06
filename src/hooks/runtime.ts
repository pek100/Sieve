/**
 * The runtime: one instance per window wiring the seams together.
 * store (core) <- poller (data) <- source (data); settings store; notice bus.
 * Tests build their own with createRuntime and inject a source and backend.
 */
import { createNoticeBus, desktopWorthy, type NoticeBus } from "@/core/notices";
import { offKeys } from "@/core/policy";
import { createStore, phase, type SieveStore } from "@/core/store";
import { trayState } from "@/core/tray";
import { browserPages, tauriDesktop, tauriPages, type Desktop, type Pages } from "@/data/desktop";
import { createPoller, realClock, type Clock, type Poller } from "@/data/poller";
import { createSettingsStore, localBackend, memoryBackend, tauriBackend, type SettingsBackend, type SettingsStore } from "@/data/settings-store";
import { createPassedChecks, type PassedChecks } from "@/core/checks";
import { createEngineController, type EngineController } from "@/data/engine-controller";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createLogController, type LogController } from "@/data/log-controller";
import { createMockSource } from "@/data/mock-source";
import { createMockFilterLists } from "@/data/filter-lists-mock";
import type { FilterListSource } from "@/data/filter-lists-source";
import { createLockController, type LockController } from "@/data/lock-controller";
import { createMockLock } from "@/data/lock-mock";
import type { LockSource } from "@/data/lock-source";
import { createMockWindowsDns, createSafetyNet, type SafetyNet, type WindowsDnsSource } from "@/data/safety-net";
import {
  createEngineSource,
  createFilterListSource,
  createLockSource,
  createSource,
  createWindowsDnsSource,
  isTauriWindow,
  sourceOptions,
  type SieveSource,
} from "@/data/source";

export interface Runtime {
  readonly isTauri: boolean;
  readonly source: SieveSource;
  readonly store: SieveStore;
  readonly poller: Poller;
  readonly settings: SettingsStore;
  readonly notices: NoticeBus;
  /** Live checks (by settings key of their data switch) that passed this session. Written by the engine controller. */
  readonly passedChecks: PassedChecks;
  /** The window's clock (the poller's): "now" for history queries. Injected in tests. */
  readonly clock: Clock;
  /** Tray and launch at startup; null outside the desktop app. */
  readonly desktop: Desktop | null;
  /** Opens public pages and says Sieve's version. Injected in tests. */
  readonly pages: Pages;
  /** The read-only safety net: it reads Windows DNS and keeps its banner true. */
  readonly safetyNet: SafetyNet;
  /** The engine seam (the Tauri commands or the mock). */
  readonly engine: EngineSource;
  /** The one owner of the store's engine part. */
  readonly engineController: EngineController;
  /** The one owner of the store's log part. */
  readonly logController: LogController;
  /** The filter list seam (the Tauri commands or the mock). */
  readonly filterLists: FilterListSource;
  /** The settings password seam (the Tauri commands or the mock). */
  readonly lock: LockSource;
  /** The one owner of the password's state and the one write gate. */
  readonly lockController: LockController;
  /** The first-run guide may take over this window. */
  readonly welcomeOnFirstRun: boolean;
}

export interface RuntimeOptions {
  source: SieveSource;
  settings: SettingsBackend;
  clock?: Clock;
  isTauri?: boolean;
  desktop?: Desktop | null;
  /** Default: the browser's. */
  pages?: Pages;
  /** Default: the mock's own Windows DNS, nothing pointed. */
  windowsDns?: WindowsDnsSource;
  /** Default: the mock engine, not installed. */
  engine?: EngineSource;
  /** Default: the mock lists, nothing loaded. */
  filterLists?: FilterListSource;
  /** Default: the mock password, none set. */
  lock?: LockSource;
  /** Default: only the desktop app offers the guide. */
  welcomeOnFirstRun?: boolean;
}

export function createRuntime(o: RuntimeOptions): Runtime {
  const store = createStore();
  const clock = o.clock ?? realClock;
  const settings = createSettingsStore(o.settings);
  const notices = createNoticeBus();
  const passedChecks = createPassedChecks();
  const desktop = o.desktop ?? null;
  const engine = o.engine ?? createMockEngine();
  const lock = o.lock ?? createMockLock();
  return {
    isTauri: o.isTauri ?? false,
    source: o.source,
    store,
    poller: createPoller({ source: o.source, store, clock }),
    settings,
    notices,
    passedChecks,
    clock,
    desktop,
    pages: o.pages ?? browserPages(),
    safetyNet: createSafetyNet({ source: o.windowsDns ?? createMockWindowsDns(), notices, clock }),
    engine,
    engineController: createEngineController({ engine, store, clock, settings, checks: passedChecks, notices }),
    logController: createLogController({ engine, store, clock }),
    filterLists: o.filterLists ?? createMockFilterLists(),
    lock,
    lockController: createLockController({ source: lock, clock, settings, notices }),
    welcomeOnFirstRun: o.welcomeOnFirstRun ?? o.isTauri ?? false,
  };
}

/** The window's runtime. Safe during static prerender (no window): inert mock and memory settings. */
export function createBrowserRuntime(): Runtime {
  if (typeof window === "undefined") {
    return createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() });
  }
  const isTauri = isTauriWindow();
  const options = sourceOptions({ search: window.location.search, isTauri });
  // The source reads the apps turned off at every sample, from this runtime's settings.
  let settings: SettingsStore | null = null;
  const rt = createRuntime({
    source: createSource(options, () => offKeys(settings?.get("apps.levels") ?? {})),
    windowsDns: createWindowsDnsSource(options),
    engine: createEngineSource(options),
    filterLists: createFilterListSource(options),
    lock: createLockSource(options),
    settings: isTauri ? tauriBackend() : localBackend(),
    isTauri,
    desktop: isTauri ? tauriDesktop() : null,
    pages: isTauri ? tauriPages() : browserPages(),
    welcomeOnFirstRun: isTauri || options.welcome,
  });
  settings = rt.settings;
  return rt;
}

/** Run the read-only safety net (read Windows DNS now and on its cadence, keep its banner true). Returns the undo. */
export function bindSafetyNet(rt: Runtime): () => void {
  return rt.safetyNet.bind();
}

/** Run the engine controller (probe now and on its cadence, follow the engine switch). Returns the undo. */
export function bindEngine(rt: Runtime): () => void {
  return rt.engineController.bind();
}

/** Run the log controller (read the engine's log tail while the engine routes). Returns the undo. */
export function bindLog(rt: Runtime): () => void {
  return rt.logController.bind();
}

/** Run the lock controller (status, idle relock) and feed it the window's activity. Returns the undo. */
export function bindLock(rt: Runtime): () => void {
  const undo = rt.lockController.bind();
  const active = () => rt.lockController.activity();
  window.addEventListener("pointerdown", active);
  window.addEventListener("keydown", active);
  return () => {
    undo();
    window.removeEventListener("pointerdown", active);
    window.removeEventListener("keydown", active);
  };
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

const NOTIFICATIONS_KEY = "notifications.desktop";
/** The title of every desktop notification. */
export const NOTIFICATION_TITLE = "Sieve";
export const NOTIFICATIONS_REFUSED = "Windows did not allow notifications, so they stayed off.";

/**
 * Desktop notifications for the problems the app already raises (`desktopWorthy`
 * on the notice bus; no-op without a desktop). Once per notice, only while the
 * setting is on and the window lacks focus; a notice seen while it was off or the
 * window in front stays in the window. Turning the setting on asks permission,
 * and a refusal turns it back off with a toast: that write only ever turns off,
 * so it does not go through the lock. A failed send is a console warning and
 * never reaches the bus. Returns the undo.
 */
export function bindNotifications(rt: Runtime, isFocused: () => boolean = () => document.hasFocus()): () => void {
  const n = rt.desktop?.notifications;
  if (!n) return () => {};
  let cancelled = false;
  const seen = new Set<number>();

  const follow = () => {
    for (const notice of rt.notices.list()) {
      if (!desktopWorthy(notice) || seen.has(notice.id)) continue;
      seen.add(notice.id);
      if (!rt.settings.get(NOTIFICATIONS_KEY) || isFocused()) continue;
      n.send(NOTIFICATION_TITLE, notice.text).catch((e: unknown) => console.warn(`Notification: ${message(e)}`));
    }
  };

  let asked = false;
  const syncPermission = async () => {
    const want = rt.settings.get(NOTIFICATIONS_KEY);
    if (cancelled || want === asked) return;
    asked = want;
    if (!want) return;
    let allowed = false;
    try {
      allowed = (await n.granted()) || (await n.request());
    } catch (e) {
      console.warn(`Notification permission: ${message(e)}`);
    }
    if (allowed || cancelled) return;
    await rt.settings.set(NOTIFICATIONS_KEY, false);
    rt.notices.push({ kind: "error", text: NOTIFICATIONS_REFUSED });
  };

  const unNotices = rt.notices.subscribe(follow);
  const unSettings = rt.settings.subscribe(() => void syncPermission());
  void rt.settings.ready.then(syncPermission);
  follow();
  return () => {
    cancelled = true;
    unNotices();
    unSettings();
  };
}

function clockTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * Keep the desktop shell in step with the window (no-op without one):
 * - the tray shows the phase (trayState) and its Pause and Resume call the
 *   same poller actions as the pause pill (Quit is Rust's: it just quits);
 * - launch at startup follows the setting `startup.launchAtLogin`, which is
 *   the source of truth: on load the OS entry is reconciled to it, and every
 *   change is applied. A failure is said in a toast.
 * Returns the undo.
 */
export function bindDesktop(rt: Runtime, fmt: (ms: number) => string = clockTime): () => void {
  const d = rt.desktop;
  if (!d) return () => {};
  let cancelled = false;

  let lastTray = "";
  const syncTray = () => {
    const s = rt.store.getState();
    const next = trayState(phase(s), s.status.pausedUntil, fmt);
    const key = JSON.stringify(next);
    if (cancelled || key === lastTray) return;
    lastTray = key;
    d.setTray(next).catch((e: unknown) => console.warn(`Tray: ${message(e)}`));
  };
  const unStore = rt.store.subscribe(syncTray);
  syncTray();

  let unTray: (() => void) | null = null;
  void d
    .onTrayAction((a) => {
      if (a.kind === "pause") rt.poller.pauseFor(a.minutes);
      else rt.poller.resume();
    })
    .then((un) => (cancelled ? un() : (unTray = un)))
    .catch((e: unknown) => console.warn(`Tray: ${message(e)}`));

  let applied: boolean | null = null;
  const syncAutostart = async () => {
    const want = rt.settings.get("startup.launchAtLogin");
    if (cancelled || want === applied) return;
    applied = want;
    try {
      if ((await d.autostart.isEnabled()) !== want) await d.autostart.set(want);
    } catch (e) {
      applied = null;
      rt.notices.push({ kind: "error", text: `Could not change launch at startup: ${message(e)}` });
    }
  };
  const unSettings = rt.settings.subscribe(() => void syncAutostart());
  void rt.settings.ready.then(syncAutostart);

  return () => {
    cancelled = true;
    unStore();
    unSettings();
    unTray?.();
  };
}

/**
 * Keep the poller in step with the settings: sampling.enabled starts and
 * stops it, sampling.intervalMs sets its cadence. Returns the undo.
 */
export function bindSampling(rt: Runtime): () => void {
  let cancelled = false;
  let lastEnabled: boolean | null = null;
  const apply = () => {
    if (cancelled) return;
    rt.poller.setIntervalMs(rt.settings.get("sampling.intervalMs"));
    const enabled = rt.settings.get("sampling.enabled");
    if (enabled === lastEnabled) return;
    lastEnabled = enabled;
    if (enabled) rt.poller.start();
    else rt.poller.stop();
  };
  const unsubscribe = rt.settings.subscribe(apply);
  void rt.settings.ready.then(apply);
  return () => {
    cancelled = true;
    unsubscribe();
    rt.poller.stop();
  };
}
