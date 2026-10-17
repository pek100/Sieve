/**
 * Live checks that passed this session, by the settings key of their data
 * switch. Observable, so the level ceiling and the settings locks follow it.
 * Writer: the DNS controller (src/data/dns-controller.ts) records a passed
 * self check and forgets it when the filter stops. Nothing is persisted: a
 * new session proves itself again.
 */
export interface PassedChecks {
  has(key: string): boolean;
  add(key: string): void;
  delete(key: string): void;
  /** Changes identity on every change, for useSyncExternalStore. */
  version(): number;
  subscribe(listener: () => void): () => void;
}

export function createPassedChecks(initial: Iterable<string> = []): PassedChecks {
  const keys = new Set(initial);
  let version = 0;
  const listeners = new Set<() => void>();
  const emit = () => {
    version += 1;
    for (const l of listeners) l();
  };
  return {
    has: (k) => keys.has(k),
    add(k) {
      if (keys.has(k)) return;
      keys.add(k);
      emit();
    },
    delete(k) {
      if (keys.delete(k)) emit();
    },
    version: () => version,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}
