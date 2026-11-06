import { afterEach, describe, expect, it, vi } from "vitest";
import type { Desktop } from "@/data/desktop";
import { createMockSource } from "@/data/mock-source";
import type { Clock } from "@/data/poller";
import { memoryBackend } from "@/data/settings-store";
import { NOTIFICATIONS_REFUSED, NOTIFICATION_TITLE, bindNotifications, createRuntime } from "./runtime";

const flush = () => new Promise<void>((r) => setTimeout(r, 0));
const still: Clock = { now: () => 1_000_000, setTimeout: () => 0, clearTimeout: () => undefined };
const ON = { schema: 4, values: { "notifications.desktop": true } };
const OFF = { schema: 4, values: {} };

function fakeDesktop(o: { granted?: boolean; allow?: boolean; failSend?: boolean } = {}) {
  const sent: [string, string][] = [];
  let requests = 0;
  const desktop: Desktop = {
    setTray: async () => {},
    onTrayAction: async () => () => {},
    autostart: { isEnabled: async () => false, set: async () => {} },
    notifications: {
      granted: async () => o.granted ?? true,
      request: async () => {
        requests += 1;
        return o.allow ?? true;
      },
      send: async (title, body) => {
        if (o.failSend) throw new Error("toast failed");
        sent.push([title, body]);
      },
    },
  };
  return { desktop, sent, requests: () => requests };
}

async function setup(d: ReturnType<typeof fakeDesktop>, stored: unknown = ON, focused = false) {
  const rt = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(stored), clock: still, desktop: d.desktop });
  const undo = bindNotifications(rt, () => focused);
  await rt.settings.ready;
  await flush();
  return { rt, undo };
}

const BANNER = { kind: "error", surface: "banner", text: "The engine stopped" } as const;

afterEach(() => vi.restoreAllMocks());

describe("desktop notifications", () => {
  it("off sends nothing, and turning on later does not replay what was seen", async () => {
    const d = fakeDesktop();
    const { rt } = await setup(d, OFF);
    rt.notices.push(BANNER);
    await flush();
    await rt.settings.set("notifications.desktop", true);
    await flush();
    rt.notices.push({ kind: "info", text: "x" });
    expect(d.sent).toEqual([]);
  });

  it("on sends once per error banner, not for a toast or an info banner", async () => {
    const d = fakeDesktop();
    const { rt } = await setup(d);
    rt.notices.push(BANNER);
    rt.notices.push({ kind: "info", surface: "banner", text: "paused" });
    rt.notices.push({ kind: "error", text: "a toast" });
    rt.notices.push({ kind: "success", text: "saved" });
    await flush();
    expect(d.sent).toEqual([[NOTIFICATION_TITLE, BANNER.text]]);
  });

  it("the window in front sends nothing", async () => {
    const d = fakeDesktop();
    const { rt } = await setup(d, ON, true);
    rt.notices.push(BANNER);
    await flush();
    expect(d.sent).toEqual([]);
  });

  it("turning on asks permission when it was not given; given, it stays on", async () => {
    const d = fakeDesktop({ granted: false, allow: true });
    const { rt } = await setup(d, OFF);
    expect(d.requests()).toBe(0);
    await rt.settings.set("notifications.desktop", true);
    await flush();
    expect(d.requests()).toBe(1);
    expect(rt.settings.get("notifications.desktop")).toBe(true);
    expect(rt.notices.list()).toEqual([]);
  });

  it("a refused permission turns the setting off with a toast", async () => {
    const d = fakeDesktop({ granted: false, allow: false });
    const { rt } = await setup(d, OFF);
    await rt.settings.set("notifications.desktop", true);
    await flush();
    expect(rt.settings.get("notifications.desktop")).toBe(false);
    expect(rt.notices.list().at(-1)).toMatchObject({ kind: "error", text: NOTIFICATIONS_REFUSED });
  });

  it("a stored on is checked at load too", async () => {
    const d = fakeDesktop({ granted: false, allow: false });
    const { rt } = await setup(d);
    expect(rt.settings.get("notifications.desktop")).toBe(false);
  });

  it("a rejected send is a console warning and never throws into the bus", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const d = fakeDesktop({ failSend: true });
    const { rt } = await setup(d);
    expect(() => rt.notices.push(BANNER)).not.toThrow();
    await flush();
    expect(warn).toHaveBeenCalledWith("Notification: toast failed");
  });

  it("no desktop, no shell notifications, and the undo stops it", async () => {
    const none = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(ON), clock: still });
    expect(() => bindNotifications(none, () => false)()).not.toThrow();
    const d = fakeDesktop();
    const { rt, undo } = await setup(d);
    undo();
    rt.notices.push(BANNER);
    await flush();
    expect(d.sent).toEqual([]);
  });
});
