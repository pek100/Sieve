import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { HealGroup } from "@/core/exclusions";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "./runtime";
import { SieveProvider } from "./sieve-provider";
import { useHealNotices } from "./use-heal-notices";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

function Host() {
  useHealNotices();
  return null;
}

function setup(engine?: EngineSource): Runtime {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(), engine });
  render(
    <SieveProvider runtime={runtime}>
      <Host />
    </SieveProvider>,
  );
  return runtime;
}

const group = (hosts: string[], rev: number, key = "0:1", exe = "client.exe"): HealGroup => ({ key, id: 1, session: 1, exe, hosts, total: hosts.length, rev });

const set = (rt: Runtime, healNotices: HealGroup[]) => act(() => rt.store.setEngine({ ...rt.store.getState().engine, healNotices }));
const toasts = (rt: Runtime) => rt.notices.list().map((n) => n.text);

afterEach(() => {
  cleanup();
  push.mockClear();
  window.history.replaceState(null, "", "/");
});

describe("heal notices", () => {
  it("one toast per group, however often the slice changes", () => {
    const rt = setup();
    const one = group(["pin.example"], 1);
    set(rt, [one]);
    set(rt, [{ ...one }]);
    set(rt, [{ ...one }]);
    expect(toasts(rt)).toEqual(["client.exe rejected Sieve's certificate for pin.example. Sieve stopped decrypting it."]);
  });

  it("another app is another toast", () => {
    const rt = setup();
    set(rt, [group(["pin.example"], 1), group(["pin.example"], 2, "0:2", "other.exe")]);
    expect(toasts(rt)).toHaveLength(2);
  });

  it("a new revision while the toast shows replaces it", () => {
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    const first = rt.notices.list()[0].id;
    set(rt, [group(["a.example", "b.example"], 2)]);
    expect(toasts(rt)).toEqual(["client.exe rejected Sieve's certificate for 2 sites. Sieve stopped decrypting them."]);
    expect(rt.notices.list()[0].id).not.toBe(first);
  });

  it("a new revision after the toast went is silent: the user was told about this app", () => {
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    act(() => rt.notices.dismiss(rt.notices.list()[0].id));
    set(rt, [group(["a.example", "b.example"], 2)]);
    expect(toasts(rt)).toEqual([]);
  });

  it("the same id from a new engine run is a new group", () => {
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    act(() => rt.notices.dismiss(rt.notices.list()[0].id));
    set(rt, [group(["a.example"], 1), group(["b.example"], 1, "1:1")]);
    expect(toasts(rt)).toHaveLength(1);
  });

  it("the action opens the filtered view", () => {
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    const notice = rt.notices.list()[0];
    expect(notice.action?.label).toBe("Show");
    act(() => notice.action?.run());
    expect(push).toHaveBeenCalledExactlyOnceWith("/settings/?exclusionsApp=client.exe&exclusionsReason=pinning#not-decrypted");
  });

  it("from the settings page the action filters in place, where a push would change nothing the view sees", () => {
    window.history.replaceState(null, "", "/settings/?source=mock");
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    act(() => rt.notices.list()[0].action?.run());
    expect(push).not.toHaveBeenCalled();
    expect(window.location.search).toBe("?source=mock&exclusionsApp=client.exe&exclusionsReason=pinning");
  });

  it("the action goes by where the user is when they click, not where the toast was pushed", () => {
    const rt = setup();
    set(rt, [group(["a.example"], 1)]);
    const pushedElsewhere = rt.notices.list()[0];
    window.history.replaceState(null, "", "/settings/?source=mock");
    act(() => pushedElsewhere.action?.run());
    expect(push, "already on the view: a push would change nothing it sees").not.toHaveBeenCalled();
    expect(window.location.search).toBe("?source=mock&exclusionsApp=client.exe&exclusionsReason=pinning");

    set(rt, [group(["a.example"], 1), group(["b.example"], 2, "0:2", "other.exe")]);
    const pushedOnSettings = rt.notices.list().find((n) => n.text.startsWith("other.exe"));
    window.history.replaceState(null, "", "/logs/");
    act(() => pushedOnSettings?.action?.run());
    expect(push).toHaveBeenCalledExactlyOnceWith("/settings/?exclusionsApp=other.exe&exclusionsReason=pinning#not-decrypted");
    expect(window.location.search, "and this page's query stays its own").toBe("");
  });

  it("a window opened over a running engine does not tell of what it did before", async () => {
    const engine = createMockEngine("idle", { heal: true });
    engine.healNotices = async () => ({ revision: 5, exclusions_revision: 1, notices: [{ id: 1, session: 1, exe: "client.exe", hosts: ["old.example"], total: 1, rev: 5 }] });
    const rt = setup(engine);
    await act(async () => {
      await vi.waitFor(() => expect(rt.store.getState().engine.exclusions).not.toBeNull());
    });
    expect(toasts(rt)).toEqual([]);
  });

  it("no groups, or none yet, say nothing", () => {
    const rt = setup();
    set(rt, []);
    expect(toasts(rt)).toEqual([]);
  });
});
