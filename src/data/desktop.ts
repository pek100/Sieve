/**
 * The desktop seam: what only the Tauri shell can do for the window. The tray
 * (state out, Pause/Resume in; Open and Quit are Rust's own) and launch at
 * startup (tauri-plugin-autostart).
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
}

/** Event name shared with src-tauri/src/tray.rs (TRAY_EVENT). */
export const TRAY_EVENT = "tray-action";

/**
 * Opening a public page, and Sieve's own version. The one seam for both: the
 * default browser in the desktop app (tauri-plugin-opener, with a capability
 * scoped to the lists' owners), a new tab in the browser preview. A report's
 * text never goes in a URL.
 */
export interface Pages {
  openExternal(url: string): Promise<void>;
  appVersion(): Promise<string>;
}

/** What the version reads outside the desktop app. */
export const BROWSER_VERSION = "browser preview";

export function tauriPages(): Pages {
  return {
    openExternal: async (url) => (await import("@tauri-apps/plugin-opener")).openUrl(url),
    appVersion: async () => (await import("@tauri-apps/api/app")).getVersion(),
  };
}

export function browserPages(): Pages {
  return {
    openExternal: async (url) => void window.open(url, "_blank", "noopener"),
    appVersion: async () => BROWSER_VERSION,
  };
}

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
  };
}
