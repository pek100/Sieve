/**
 * The runtime: one instance per window wiring the seams together.
 * store (core) <- poller (data) <- source (data); settings store; notice bus.
 * Tests build their own with createRuntime and inject a source and backend.
 */
import { createNoticeBus, type NoticeBus } from "@/core/notices";
import { offKeys } from "@/core/policy";
import { createStore, phase, type SieveStore } from "@/core/store";
import { trayState } from "@/core/tray";
import { tauriDesktop, type Desktop } from "@/data/desktop";
import { createPoller, realClock, type Clock, type Poller } from "@/data/poller";
import { createSettingsStore, localBackend, memoryBackend, tauriBackend, type SettingsBackend, type SettingsStore } from "@/data/settings-store";
import { createPassedChecks, type PassedChecks } from "@/core/checks";
import { createDnsController, type DnsController } from "@/data/dns-controller";
import { createMockDns } from "@/data/dns-mock";
import type { DnsSource } from "@/data/dns-source";
import { createMockSource } from "@/data/mock-source";
import { createDnsSource, createSource, isTauriWindow, sourceOptions, type SieveSource } from "@/data/source";

export interface Runtime {
  readonly isTauri: boolean;
  readonly source: SieveSource;
  readonly store: SieveStore;
  readonly poller: Poller;
  readonly settings: SettingsStore;
  readonly notices: NoticeBus;
  /** Live checks (by settings key of their data switch) that passed this session. Written by the DNS controller. */
  readonly passedChecks: PassedChecks;
  /** The window's clock (the poller's): "now" for history queries. Injected in tests. */
  readonly clock: Clock;
  /** Tray and launch at startup; null outside the desktop app. */
  readonly desktop: Desktop | null;
  /** The DNS seam (Tauri commands or the mock). */
  readonly dns: DnsSource;
  /** The one owner of DNS state; components call its actions through hooks. */
  readonly dnsController: DnsController;
}

export interface RuntimeOptions {
  source: SieveSource;
  settings: SettingsBackend;
  clock?: Clock;
  isTauri?: boolean;
  desktop?: Desktop | null;
  /** Default: the mock DNS, scenario off. */
  dns?: DnsSource;
}

export function createRuntime(o: RuntimeOptions): Runtime {
  const store = createStore();
  const clock = o.clock ?? realClock;
  const settings = createSettingsStore(o.settings);
  const notices = createNoticeBus();
  const passedChecks = createPassedChecks();
  const desktop = o.desktop ?? null;
  const dns = o.dns ?? createMockDns({ seed: 1, now: clock.now });
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
    dns,
    dnsController: createDnsController({
      dns,
      store,
      settings,
      notices,
      checks: passedChecks,
      clock,
      exit: desktop ? () => desktop.quit() : null,
    }),
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
    dns: createDnsSource(options),
    settings: isTauri ? tauriBackend() : localBackend(),
    isTauri,
    desktop: isTauri ? tauriDesktop() : null,
  });
  settings = rt.settings;
  return rt;
}

/** Run the DNS controller (load, safety rule, follow the switches, poll). Returns the undo. */
export function bindDns(rt: Runtime): () => void {
  return rt.dnsController.bind();
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function clockTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * Keep the desktop shell in step with the window (no-op without one):
 * - the tray shows the phase (trayState) and its Pause and Resume call the
 *   same poller actions as the pause pill;
 * - tray Quit and the window's close go to the DNS controller, which asks
 *   first while Windows points at Sieve;
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
      else if (a.kind === "resume") rt.poller.resume();
      else rt.dnsController.requestQuit();
    })
    .then((un) => (cancelled ? un() : (unTray = un)))
    .catch((e: unknown) => console.warn(`Tray: ${message(e)}`));

  // Closing the window ends the app: while Windows points at Sieve, ask first.
  let unClose: (() => void) | null = null;
  void d
    .onCloseRequested(() => {
      if (!rt.dnsController.holdClose()) return false;
      rt.dnsController.requestQuit();
      return true;
    })
    .then((un) => (cancelled ? un() : (unClose = un)))
    .catch((e: unknown) => console.warn(`Close: ${message(e)}`));

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
    unClose?.();
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
