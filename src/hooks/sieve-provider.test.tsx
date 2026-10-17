import { act, render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { TrayAction, TrayState } from "@/core/tray";
import type { Desktop } from "@/data/desktop";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "./runtime";
import { SieveProvider } from "./sieve-provider";

/** Timers never fire: only explicit poller calls change the status. */
const still: Clock = { now: () => 2_000_000, setTimeout: () => 0, clearTimeout: () => undefined };

/**
 * The provider is where the window binds its runtime: sampling to the
 * settings and the desktop shell (tray, launch at startup) to the store.
 * Mounting it binds both; unmounting undoes both.
 */
describe("SieveProvider binds the runtime for as long as it is mounted", () => {
  it("sampling starts from the settings, the tray follows the store and drives the poller, unmount undoes both", async () => {
    const trays: TrayState[] = [];
    const tray: { fire: ((a: TrayAction) => void) | null } = { fire: null };
    const desktop: Desktop = {
      setTray: async (s) => void trays.push(s),
      onTrayAction: async (cb) => {
        tray.fire = cb;
        return () => (tray.fire = null);
      },
      autostart: { isEnabled: async () => false, set: async () => {} },
      onCloseRequested: async () => () => {},
      quit: async () => {},
    };
    const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), clock: still, desktop });

    const view = render(
      <SieveProvider runtime={rt}>
        <p>child</p>
      </SieveProvider>,
    );
    await act(async () => {
      await rt.settings.ready;
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(rt.store.getState().status.running).toBe(true);
    expect(tray.fire).not.toBeNull();

    act(() => tray.fire?.({ kind: "pause", minutes: 5 }));
    expect(rt.store.getState().status.pausedUntil).toBe(2_000_000 + 5 * 60_000);
    expect(trays.at(-1)).toMatchObject({ canPause: false, canResume: true, dim: true });

    view.unmount();
    expect(tray.fire).toBeNull();
    expect(rt.store.getState().status.running).toBe(false);
    const n = trays.length;
    rt.poller.pauseFor(1);
    expect(trays.length).toBe(n);
  });
});
