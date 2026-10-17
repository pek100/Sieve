/**
 * The desktop seam: what only the Tauri shell can do for the window. The tray
 * (state out, Pause/Resume/Quit in), launch at startup (tauri-plugin-autostart),
 * the window's close request and quitting the app.
 * The browser and tests have no desktop (null) or inject a fake.
 */
import { invoke } from "@tauri-apps/api/core";
import { parseTrayAction, type TrayAction, type TrayState } from "@/core/tray";

export interface Desktop {
  setTray(state: TrayState): Promise<void>;
  /** Subscribe to tray menu actions; resolves to the unsubscribe. */
  onTrayAction(cb: (a: TrayAction) => void): Promise<() => void>;
  autostart: {
    isEnabled(): Promise<boolean>;
    set(on: boolean): Promise<void>;
  };
  /**
   * Subscribe to the window's close (close button, Alt+F4). `hold` returning
   * true keeps the window open. Resolves to the unsubscribe.
   */
  onCloseRequested(hold: () => boolean): Promise<() => void>;
  /** End the app (Rust `app_quit`). */
  quit(): Promise<void>;
}

/** Event name shared with src-tauri/src/tray.rs (TRAY_EVENT). */
export const TRAY_EVENT = "tray-action";

export function tauriDesktop(): Desktop {
  const autostart = import("@tauri-apps/plugin-autostart");
  return {
    setTray: (state) => invoke("tray_set_state", { state }),
    async onTrayAction(cb) {
      const { listen } = await import("@tauri-apps/api/event");
      return listen<unknown>(TRAY_EVENT, (e) => {
        const a = parseTrayAction(e.payload);
        if (a) cb(a);
      });
    },
    autostart: {
      isEnabled: async () => (await autostart).isEnabled(),
      set: async (on) => {
        const m = await autostart;
        await (on ? m.enable() : m.disable());
      },
    },
    async onCloseRequested(hold) {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      return getCurrentWindow().onCloseRequested((e) => {
        if (hold()) e.preventDefault();
      });
    },
    quit: () => invoke("app_quit"),
  };
}
