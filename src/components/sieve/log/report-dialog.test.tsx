import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NoticeToaster } from "@/components/sieve/shell/notice-toaster";
import type { Pages } from "@/data/desktop";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import type { EngineProbe, EngineStatus, ListFact } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { ReportDialog } from "./report-dialog";

vi.mock("next/navigation", () => ({ usePathname: () => "/log/" }));
vi.setConfig({ testTimeout: 20_000 });

const FULL_URL = "https://news.example.com/article/42?utm_source=mail&token=s3cret#top";
const STRIPPED = "https://news.example.com/article/42";
const FIREFOX = "C:\\Program Files\\Mozilla Firefox\\firefox.exe";
const ADGUARD_ISSUES = "https://github.com/AdguardTeam/AdguardFilters/issues";
const UBO_ISSUES = "https://github.com/uBlockOrigin/uAssets/issues";

const clipboard = vi.fn<(text: string) => Promise<void>>(async () => undefined);

/** Every way a page could send something, recorded. Nothing here may be called. */
const sent: string[] = [];
const realFetch = globalThis.fetch;
const realXhr = globalThis.XMLHttpRequest;
const realSocket = globalThis.WebSocket;

beforeEach(() => {
  sent.length = 0;
  // jsdom has none; Radix Select calls it on the open list.
  Element.prototype.scrollIntoView = () => {};
  clipboard.mockClear();
  clipboard.mockImplementation(async () => undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboard } });
  globalThis.fetch = (async (u: unknown) => {
    sent.push(`fetch ${String(u)}`);
    return new Response();
  }) as typeof fetch;
  globalThis.XMLHttpRequest = class {
    open(_m: string, u: string) {
      sent.push(`xhr ${u}`);
    }
    send() {
      sent.push("xhr send");
    }
    setRequestHeader() {}
  } as unknown as typeof XMLHttpRequest;
  globalThis.WebSocket = class {
    constructor(u: string) {
      sent.push(`ws ${u}`);
    }
  } as unknown as typeof WebSocket;
  Object.defineProperty(navigator, "sendBeacon", { configurable: true, value: (u: string) => (sent.push(`beacon ${u}`), true) });
});

afterEach(() => {
  globalThis.fetch = realFetch;
  globalThis.XMLHttpRequest = realXhr;
  globalThis.WebSocket = realSocket;
});

function fakePages(version = "1.2.3") {
  const opened: string[] = [];
  const pages: Pages = {
    openExternal: async (url) => void opened.push(url),
    appVersion: async () => version,
  };
  return { pages, opened };
}

/** The mock engine with its `hosts` status's facts replaced. */
function withFacts(lists: ListFact[] | null): EngineSource {
  const base = createMockEngine("hosts");
  return {
    ...base,
    probe: async () => {
      const p = (await base.probe()) as EngineProbe;
      if (p.pipe?.kind !== "welcome") return p;
      const status: EngineStatus = { ...p.pipe.status };
      if (lists === null) delete status.filter;
      else status.filter = { lists, resource_pin: "sha256:9" };
      return { ...p, pipe: { ...p.pipe, status } };
    },
  };
}

async function setup(seed: { url: string | null; exe: string | null }, engine: EngineSource = createMockEngine("hosts")) {
  const { pages, opened } = fakePages();
  const onClose = vi.fn();
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values: { "filtering.engine": true } }), engine, pages });
  render(
    <SieveProvider runtime={runtime}>
      <ReportDialog seed={seed} onClose={onClose} />
      <NoticeToaster />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  await vi.waitFor(() => expect(runtime.store.getState().engine.probe).not.toBeNull());
  await vi.waitFor(() => expect(text()).toContain("Sieve version: 1.2.3"));
  return { runtime, opened, onClose };
}

const text = () => screen.getByRole<HTMLTextAreaElement>("textbox", { name: "The report" }).value;
const urlField = () => screen.getByRole<HTMLInputElement>("textbox", { name: "Page URL" });
const openButton = () => screen.getByRole("button", { name: "Open issue page" });

describe("the report", () => {
  it("holds the listed fields and no pid, session, IP or flow id", async () => {
    await setup({ url: FULL_URL, exe: FIREFOX });
    const t = text();
    expect(t).toContain(`Page URL: ${STRIPPED}`);
    expect(t).toContain("Browser: firefox.exe");
    expect(t).toContain("AdGuard Base filter: 2.3.72");
    expect(t).toContain("uBlock filters: version not known");
    expect(t).toContain("Resource library pin: sha256:0f4e2c7a");
    expect(t).toContain("Sieve version: 1.2.3");
    expect(t).not.toMatch(/pid|session|flow|192\.0\.2|\b4242\b/i);
  });

  it("the prefilled URL has no query or fragment; the button brings them back; then they stay in the report", async () => {
    await setup({ url: FULL_URL, exe: FIREFOX });
    expect(urlField().value).toBe(STRIPPED);
    expect(text()).not.toContain("token");
    expect(text()).not.toContain("s3cret");
    await userEvent.click(screen.getByRole("button", { name: "Add the query string back" }));
    expect(urlField().value).toBe(FULL_URL);
    expect(text()).toContain(`Page URL: ${FULL_URL}`);
    expect(screen.queryByRole("button", { name: "Add the query string back" })).toBeNull();
  });

  it("no restore button for a URL with no query", async () => {
    await setup({ url: STRIPPED, exe: null });
    expect(screen.queryByRole("button", { name: "Add the query string back" })).toBeNull();
  });

  it("an edited URL is used verbatim", async () => {
    await setup({ url: FULL_URL, exe: FIREFOX });
    fireEvent.change(urlField(), { target: { value: "https://other.example/typed?kept=1" } });
    expect(text()).toContain("Page URL: https://other.example/typed?kept=1");
  });

  it("from the app sheet there is no URL yet, and it says so", async () => {
    await setup({ url: null, exe: FIREFOX });
    expect(urlField().value).toBe("");
    expect(text()).toContain("Page URL: not known");
    expect(text()).toContain("Browser: firefox.exe");
  });
});

describe("Open issue page", () => {
  it("an AdGuard list's row opens AdGuard's issues; the URL has no query and not the report", async () => {
    const { runtime, opened } = await setup({ url: "https://ads.example.com/", exe: "C:\\Program Files\\Mozilla Firefox\\firefox.exe" });
    act(() =>
      runtime.store.setLog({
        ...runtime.store.getState().log,
        rows: [{ seq: 1, row: { id: 1, t: 1, flow_id: 1, pid: 1, exe: FIREFOX, session: 1, kind: "tls", host: "ads.example.com", remote: "", url: null, request_type: null, outcome: { kind: "blocked" }, rule: "||ads.example.com^", list: "adguard-base" } }],
      }),
    );
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toEqual([ADGUARD_ISSUES]));
    expect(opened[0]).not.toContain("?");
    expect(opened[0]).not.toContain("ads.example.com");
    expect(clipboard).toHaveBeenCalledTimes(1);
    expect(clipboard.mock.calls[0][0]).toBe(text());
  });

  it("a uAssets list's row opens uAssets' issues", async () => {
    const { runtime, opened } = await setup({ url: "https://news.example.com/article/42", exe: null });
    act(() =>
      runtime.store.setLog({
        ...runtime.store.getState().log,
        rows: [{ seq: 1, row: { id: 1, t: 1, flow_id: 1, pid: 1, exe: FIREFOX, session: 1, kind: "tls", host: "news.example.com", remote: "", url: null, request_type: null, outcome: { kind: "hidden", elements: 1 }, rule: "news.example.com##.x", list: "ubo-filters" } }],
      }),
    );
    expect(text()).toContain("news.example.com##.x (uBlock filters)");
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toEqual([UBO_ISSUES]));
  });

  it("a row with no list gives the first list", async () => {
    const { opened } = await setup({ url: "https://x.example/", exe: null });
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toEqual([ADGUARD_ISSUES]));
  });

  it("no facts disables it, with the reason", async () => {
    await setup({ url: "https://x.example/", exe: null }, withFacts(null));
    expect(openButton()).toBeDisabled();
    expect(document.querySelector("[data-report-no-page]")).toHaveTextContent("has not reported its filter lists");
    expect(text()).toContain("Lists:\n- none reported");
  });

  it("a homepage that is not https gives none", async () => {
    const http: ListFact = { id: "plain", title: "Plain list", homepage: "http://list.example/repo", version: null, applied: 1, skipped: 0 };
    await setup({ url: "https://x.example/", exe: null }, withFacts([http]));
    expect(openButton()).toBeDisabled();
    expect(document.querySelector("[data-report-no-page]")).toHaveTextContent("no public issue page");
  });

  it("a refused clipboard leaves a notice and the text selectable, and the page still opens", async () => {
    const { opened } = await setup({ url: "https://x.example/", exe: null });
    clipboard.mockRejectedValueOnce(new Error("denied"));
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toEqual([ADGUARD_ISSUES]));
    expect(await screen.findByText(/Could not copy/)).toBeInTheDocument();
    expect(text()).toContain("Page URL: https://x.example/");
  });

  it("the list can be changed, and that is the page that opens", async () => {
    const { opened } = await setup({ url: "https://x.example/", exe: null });
    await userEvent.click(screen.getByRole("combobox", { name: "Goes to the issue page of" }));
    await userEvent.click(await screen.findByRole("option", { name: "uBlock filters" }));
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toEqual([UBO_ISSUES]));
  });
});

describe("nothing is sent", () => {
  it("opening, editing, Copy report and Open issue page record zero requests; the clipboard got the text; the page opened once", async () => {
    const { opened } = await setup({ url: FULL_URL, exe: FIREFOX });
    fireEvent.change(urlField(), { target: { value: "https://edited.example/page" } });
    await userEvent.click(screen.getByRole("button", { name: "Copy report" }));
    await vi.waitFor(() => expect(clipboard).toHaveBeenCalledTimes(1));
    expect(clipboard.mock.calls[0][0]).toContain("Page URL: https://edited.example/page");
    await userEvent.click(openButton());
    await vi.waitFor(() => expect(opened).toHaveLength(1));
    expect(clipboard).toHaveBeenCalledTimes(2);
    expect(sent).toEqual([]);
    expect(opened[0]).not.toContain("edited.example");
  });

  it("Done closes it", async () => {
    const { onClose } = await setup({ url: null, exe: null });
    await userEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Done" }));
    expect(onClose).toHaveBeenCalled();
  });
});
