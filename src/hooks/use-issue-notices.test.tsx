import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { desktopWorthy } from "@/core/notices";
import { startedFailingText } from "@/core/issues";
import { createMockSource } from "@/data/mock-source";
import type { AppIssues, Issues, Problem } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "./runtime";
import { SieveProvider } from "./sieve-provider";
import { appHref, useIssueNotices } from "./use-issue-notices";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

function Host() {
  useIssueNotices();
  return null;
}

function setup(): Runtime {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() });
  render(
    <SieveProvider runtime={runtime}>
      <Host />
    </SieveProvider>,
  );
  return runtime;
}

const T = 1_793_000_000_000;
const failing = (key: string, cause: Problem["cause"] = "sieve"): AppIssues => ({
  key,
  exe: `${key}.exe`,
  session: 1,
  since_ms: T,
  flows: 5,
  retried: 0,
  recovered: 0,
  problems: [{ signal: cause === "network" ? "connect_timeout" : "app_refused_certificate", cause, host: "cdn.example", count: 3, first_ms: T + 1, last_ms: T + 2 }],
});
const answer = (apps: AppIssues[], run = 1): Issues => ({ run, revision: apps.length, apps, dropped: 0 });
const set = (rt: Runtime, issues: Issues) => act(() => rt.store.setEngine({ ...rt.store.getState().engine, issues }));

afterEach(() => {
  cleanup();
  push.mockClear();
});

describe("issue notices", () => {
  it("what the engine held at the first read is not news; a newly failing app is one gentle notice, asking for the desktop", () => {
    const rt = setup();
    set(rt, answer([failing("old")]));
    expect(rt.notices.list()).toEqual([]);
    set(rt, answer([failing("old"), failing("updater")]));
    set(rt, answer([failing("old"), failing("updater")]));
    const told = rt.notices.list();
    expect(told.map((n) => n.text)).toEqual([startedFailingText("updater.exe")]);
    expect(told[0].kind).toBe("info");
    expect(desktopWorthy(told[0]), "sent only while the user's notification setting is on").toBe(true);
    act(() => told[0].action?.run());
    expect(push).toHaveBeenCalledExactlyOnceWith(appHref("updater"));
  });

  it("failures the network explains tell nothing", () => {
    const rt = setup();
    set(rt, answer([]));
    set(rt, answer([failing("game", "network")]));
    expect(rt.notices.list()).toEqual([]);
  });

  it("a new engine run may tell of the same app again", () => {
    const rt = setup();
    set(rt, answer([]));
    set(rt, answer([failing("game")], 1));
    set(rt, answer([failing("game")], 2));
    expect(rt.notices.list()).toHaveLength(2);
  });
});
