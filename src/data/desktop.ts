/**
 * The desktop seam: what only the Tauri shell can do for the window. The tray
 * (state out, Pause/Resume in; Open and Quit are Rust's own), launch at
 * startup (tauri-plugin-autostart) and desktop notifications.
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
  /** Desktop notifications (tauri-plugin-notification); null when this shell has none. */
  notifications: DesktopNotifications | null;
}

export interface DesktopNotifications {
  granted(): Promise<boolean>;
  /** Asks Windows; resolves to whether it is allowed now. */
  request(): Promise<boolean>;
  send(title: string, body: string): Promise<void>;
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
  const notification = import("@tauri-apps/plugin-notification");
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
    notifications: {
      granted: async () => (await notification).isPermissionGranted(),
      request: async () => (await (await notification).requestPermission()) === "granted",
      send: async (title, body) => (await notification).sendNotification({ title, body }),
    },
  };
}
