/**
 * The runtime: one instance per window wiring the seams together.
 * store (core) <- poller (data) <- source (data); settings store; notice bus.
 * Tests build their own with createRuntime and inject a source and backend.
 */
import { createNoticeBus, type NoticeBus } from "@/core/notices";
import { createStore, type SieveStore } from "@/core/store";
import { createPoller, type Clock, type Poller } from "@/data/poller";
import { createSettingsStore, localBackend, memoryBackend, tauriBackend, type SettingsBackend, type SettingsStore } from "@/data/settings-store";
import { createMockSource } from "@/data/mock-source";
import { isTauriWindow, resolveSource, type SieveSource } from "@/data/source";

export interface Runtime {
  readonly isTauri: boolean;
  readonly source: SieveSource;
  readonly store: SieveStore;
  readonly poller: Poller;
  readonly settings: SettingsStore;
  readonly notices: NoticeBus;
  /** Live checks (by settings key of their data switch) that passed this session. None yet. */
  readonly passedChecks: ReadonlySet<string>;
}

export interface RuntimeOptions {
  source: SieveSource;
  settings: SettingsBackend;
  clock?: Clock;
  isTauri?: boolean;
}

export function createRuntime(o: RuntimeOptions): Runtime {
  const store = createStore();
  return {
    isTauri: o.isTauri ?? false,
    source: o.source,
    store,
    poller: createPoller({ source: o.source, store, clock: o.clock }),
    settings: createSettingsStore(o.settings),
    notices: createNoticeBus(),
    passedChecks: new Set<string>(),
  };
}

/** The window's runtime. Safe during static prerender (no window): inert mock and memory settings. */
export function createBrowserRuntime(): Runtime {
  if (typeof window === "undefined") {
    return createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() });
  }
  const isTauri = isTauriWindow();
  return createRuntime({
    source: resolveSource({ search: window.location.search, isTauri }),
    settings: isTauri ? tauriBackend() : localBackend(),
    isTauri,
  });
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
