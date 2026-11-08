import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NoticeToaster } from "@/components/sieve/shell/notice-toaster";
import { EMPTY_LOG, LOG_POLL_MS, LOG_SHOWN } from "@/core/log";
import { createMockEngine, MOCK_LOG_ERROR, type EngineScenario } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import logFixture from "@/data/fixtures/engine-log-v1.json";
import { createMockSource } from "@/data/mock-source";
import { LOG_TAIL_VERSION, type LogEntry, type LogOutcome, type LogRow } from "@/data/protocol";
import { memoryBackend, type SettingsBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { LogScreen } from "./log-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/log/" }));
vi.setConfig({ testTimeout: 20_000 });

const FIXTURE_ROWS = logFixture.rows as unknown as LogEntry[];
const clipboard = vi.fn<(text: string) => Promise<void>>(async () => undefined);

beforeEach(() => {
  clipboard.mockClear();
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: clipboard } });
});

/** The mock engine, with its first log read made at once rather than after a tick. */
async function setup(engine: EngineSource | EngineScenario = "hosts", stored?: unknown, settings?: SettingsBackend) {
  const runtime = createRuntime({
    source: createMockSource({ seed: 1 }),
    settings: settings ?? memoryBackend(stored ?? { schema: 5, values: { "filtering.engine": true } }),
    engine: typeof engine === "string" ? createMockEngine(engine) : engine,
  });
  render(
    <SieveProvider runtime={runtime}>
      <LogScreen />
      <NoticeToaster />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return runtime;
}

/** Waits for the mock's first read: the ring holds every fixture row. */
async function withRows(engine: EngineSource | EngineScenario = "hosts", stored?: unknown, settings?: SettingsBackend) {
  const rt = await setup(engine, stored, settings);
  await vi.waitFor(() => expect(screen.getAllByTestId("log-row").length).toBeGreaterThan(0), { timeout: LOG_POLL_MS * 4 });
  // Reads go on; the tests need a still list.
  act(() => rt.logController.pause());
  return rt;
}

const rows = () => screen.queryAllByTestId("log-row");
const rowOf = (host: string) => rows().find((r) => r.querySelector("[data-log-host]")?.textContent === host)!;
/** A TLS flow with no name: the row knows it only by its address. */
const ipRow = (host: string, outcome: LogOutcome): LogEntry => ({ seq: 1, row: { ...(FIXTURE_ROWS[0].row as LogRow), kind: "tls", url: null, rule: null, list: null, host, outcome } });

describe("the Log screen", () => {
  it("says each outcome in words, the blocked colour only on Blocked", async () => {
    await withRows();
    const words = new Set(rows().map((r) => r.querySelector("[data-log-outcome]")?.textContent));
    for (const w of ["Blocked", "Redirected", "Parameters removed", "Hidden 3 elements", "Scriptlets", "Passed through (no rule matched)", "Passed through (exception rule)", "Passed through (app is off)", "Not decrypted (no rule matched)"]) {
      expect(words, w).toContain(w);
    }
    for (const r of rows()) {
      const outcome = r.querySelector("[data-log-outcome]")!;
      expect(outcome.className.includes("text-blocked"), outcome.textContent ?? "").toBe(outcome.textContent === "Blocked");
    }
  });

  it("the filters: All, Blocked, Modified, Not decrypted", async () => {
    await withRows();
    const filter = screen.getByRole("radiogroup", { name: "Show" });
    const kinds = () => new Set(rows().map((r) => r.getAttribute("data-outcome")));
    await userEvent.click(within(filter).getByRole("radio", { name: "Blocked" }));
    expect(kinds()).toEqual(new Set(["blocked"]));
    await userEvent.click(within(filter).getByRole("radio", { name: "Modified" }));
    expect(kinds()).toEqual(new Set(["redirected", "params_removed", "hidden", "scriptlets"]));
    await userEvent.click(within(filter).getByRole("radio", { name: "Not decrypted" }));
    expect(kinds()).toEqual(new Set(["not_decrypted"]));
    await userEvent.click(within(filter).getByRole("radio", { name: "All" }));
    expect(rows().length).toBeGreaterThanOrEqual(FIXTURE_ROWS.length);
  });

  it("search covers host, exe, rule and the list's name; no match says so and offers the way back", async () => {
    await withRows();
    const search = screen.getByRole("searchbox", { name: "Search the log" });
    fireEvent.change(search, { target: { value: "tracker.example" } });
    expect(rows().map((r) => r.querySelector("[data-log-host]")?.textContent)).toEqual(["tracker.example.org"]);
    fireEvent.change(search, { target: { value: "sync.exe" } });
    expect(rows().map((r) => r.querySelector("[data-log-host]")?.textContent).every((h) => h === "198.51.100.25")).toBe(true);
    fireEvent.change(search, { target: { value: "removeparam" } });
    expect(rows()).toHaveLength(1);
    fireEvent.change(search, { target: { value: "AdGuard Base" } });
    expect(rows().length).toBeGreaterThan(0);
    for (const r of rows()) expect(r).toHaveTextContent("AdGuard Base filter");
    fireEvent.change(search, { target: { value: "zzzz" } });
    expect(screen.getByText("No row matches")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show every row" }));
    expect(rows().length).toBeGreaterThan(0);
  });

  it("pause stops the reads and clear empties the rows; resume goes on with new rows only", async () => {
    const logTail = vi.fn(createMockEngine("hosts").logTail);
    const rt = await withRows({ ...createMockEngine("hosts"), logTail });
    expect(screen.getByRole("button", { name: "Resume the log" })).toHaveAttribute("aria-pressed", "true");
    const before = logTail.mock.calls.length;
    await act(() => new Promise((r) => setTimeout(r, LOG_POLL_MS * 1.5)));
    expect(logTail.mock.calls.length).toBe(before);

    await userEvent.click(screen.getByRole("button", { name: "Clear the log" }));
    expect(rows()).toHaveLength(0);
    expect(rt.store.getState().log.cursor).toBeGreaterThan(0);
    expect(screen.getByText("Nothing yet")).toBeInTheDocument();
    expect(screen.getByText(/The log is paused/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Resume the log" }));
    await vi.waitFor(() => expect(rows().length).toBeGreaterThan(0), { timeout: LOG_POLL_MS * 4 });
    // The mock cycles one host-level row a read: nothing of the first batch came back.
    expect(rows().length).toBeLessThan(FIXTURE_ROWS.length);
    act(() => rt.logController.pause());
  });

  it.each([
    ["missing", /not installed on this computer/],
    ["stopped", /service is not running/],
    ["idle", /no traffic goes through it/],
    ["adguard", /AdGuard is filtering this computer/],
    ["vpn", /Paused while AdGuard VPN is connected/],
    ["error", /could not read the engine's state/],
  ] as [EngineScenario, RegExp][])("engine %s: the empty state says what the engine is doing, from its facts", async (scenario, body) => {
    // Idle means the switch is off; on, the mock engine would start routing.
    await setup(scenario, scenario === "idle" ? { schema: 5, values: {} } : undefined);
    await vi.waitFor(() => expect(screen.getByRole("region", { name: "Log rows" })).toHaveTextContent(body));
    expect(screen.getByText("Nothing to show")).toBeInTheDocument();
    expect(rows()).toHaveLength(0);
    expect(screen.getByRole("button", { name: "Clear the log" })).toBeDisabled();
  });

  it("the engine routes and nothing arrived yet: it says rows will come", async () => {
    await setup({ ...createMockEngine("hosts"), logTail: async (since) => ({ v: LOG_TAIL_VERSION, next: since, dropped: 0, rows: [], skipped: 0 }) });
    await vi.waitFor(() => expect(screen.getByText("Nothing yet")).toBeInTheDocument());
    expect(screen.getByText(/Rows appear here/)).toBeInTheDocument();
  });

  it("a failed read says so; the rows stay", async () => {
    const good = createMockEngine("hosts");
    let fail = false;
    const rt = await setup({
      ...good,
      logTail: async (since) => {
        if (fail) throw new Error(MOCK_LOG_ERROR);
        return good.logTail(since);
      },
    });
    await vi.waitFor(() => expect(rows().length).toBeGreaterThan(0), { timeout: LOG_POLL_MS * 4 });
    const n = rows().length;
    fail = true;
    await vi.waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(MOCK_LOG_ERROR), { timeout: LOG_POLL_MS * 4 });
    expect(rows().length).toBeGreaterThanOrEqual(n);
    act(() => rt.logController.pause());
  });

  it("degraded data: a row with every optional field null, a malformed ring entry and an old row render, in the boundary", async () => {
    const rt = await setup("missing");
    const bare = { id: 1, t: 1_760_000_000_000, flow_id: 1, pid: null, exe: null, session: null, kind: "other", host: "198.51.100.1", remote: "", url: null, request_type: null, outcome: { kind: "blocked" }, rule: null, list: null };
    const malformed = [
      { seq: 1, row: bare },
      null,
      { seq: 2 },
      { seq: 3, row: null },
      { seq: 4, row: { host: "partial.example" } },
      { seq: 5, row: { t: 1, host: "weird.example", outcome: { kind: "from_the_future" } } },
    ] as unknown as LogEntry[];
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: malformed }));
    expect(rows().map((r) => r.querySelector("[data-log-host]")?.textContent)).toEqual(["weird.example", "partial.example", "198.51.100.1"]);
    expect(screen.queryByText("This could not load")).toBeNull();
    // Their details open too.
    await userEvent.click(screen.getByRole("button", { name: /^198\.51\.100\.1, Blocked, Unknown app/ }));
    const sheet = await screen.findByRole("dialog");
    expect(sheet).toHaveTextContent("No rule");
    expect(sheet).toHaveTextContent("No list");
    await userEvent.keyboard("{Escape}");
    await userEvent.click(rowOf("partial.example").querySelector("button")!);
    expect(await screen.findByRole("dialog")).toHaveTextContent("Unknown");
  });

  it("a render crash stays inside the screen's boundary", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const rt = await setup("missing");
    // A getter that throws is the one thing the guards above cannot absorb: the boundary must.
    const bomb = {
      seq: 1,
      row: {
        get host(): string {
          throw new Error("kaboom");
        },
      },
    } as unknown as LogEntry;
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: [bomb] }));
    expect(screen.getByText("This could not load")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Log" })).toBeInTheDocument();
    spy.mockRestore();
  });

  it("shows the newest LOG_SHOWN and counts the rest", async () => {
    const rt = await setup("missing");
    const many: LogEntry[] = Array.from({ length: LOG_SHOWN + 3 }, (_, i) => ({ seq: i + 1, row: { ...(FIXTURE_ROWS[0].row as LogRow), id: i } }));
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: many, dropped: 2, skipped: 1 }));
    expect(rows()).toHaveLength(LOG_SHOWN);
    expect(screen.getByTestId("log-more")).toHaveTextContent("3 more not shown");
    expect(screen.getByTestId("log-lost")).toHaveTextContent("2 rows dropped before Sieve read them. 1 row could not be read.");
  });
});

describe("row details", () => {
  it("say the rule, the list and the request's facts; the actions are the row's", async () => {
    await withRows();
    await userEvent.click(rows().find((r) => r.getAttribute("data-outcome") === "params_removed")!.querySelector("button")!);
    const sheet = await screen.findByRole("dialog");
    expect(sheet).toHaveTextContent("$removeparam=utm_source");
    expect(sheet).toHaveTextContent("AdGuard Base filter");
    expect(sheet).toHaveTextContent("https://news.example.com/article/42?utm_source=mail&token=s3cret#top");
    expect(sheet).toHaveTextContent("document");
    expect(sheet).toHaveTextContent("192.0.2.13:443");
    expect(sheet).toHaveTextContent("firefox.exe");
    const buttons = within(sheet.querySelector<HTMLElement>("[data-log-details-actions]")!).getAllByRole("button").map((b) => b.textContent);
    expect(buttons).toEqual(["Copy URL", "Do not decrypt this site", "Report a broken site"]);
  });

  it("say what tracking protection changed, and the row says it in its outcome column", async () => {
    const rt = await setup("missing");
    const base = FIXTURE_ROWS[1].row as LogRow;
    const row: LogRow = { ...base, url: "https://shop.example.net/a", request_type: "document", changes: [{ what: "queryParams", count: 3 }, { what: "searchQueries", count: 1 }, { what: "gpc", count: 2 }] };
    const one: LogRow = { ...base, id: 2, url: "https://shop.example.net/b", request_type: "image", changes: [{ what: "referrer", count: 1 }, { what: "gpc", count: 2 }] };
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: [{ seq: 1, row }, { seq: 2, row: one }] }));
    const [newest, older] = rows();
    expect(newest.querySelector("[data-log-outcome]")).toHaveTextContent("Removed the page you came from");
    expect(older.querySelector("[data-log-outcome]"), "the header signals are not counted in the column").toHaveTextContent("Tracking protection made 2 changes");
    await userEvent.click(older.querySelector("button")!);
    const sheet = await screen.findByRole("dialog");
    const changes = within(sheet.querySelector<HTMLElement>("[data-log-changes]")!).getAllByRole("listitem").map((li) => li.textContent);
    expect(changes, "the details keep every change, the signals too").toEqual(["Removed 3 tracking parameters", "Told the site only where you came from, not the page", "Sent Global Privacy Control and Do Not Track"]);
  });
});

/**
 * The newest notice's Undo, through this runtime's bus: sonner's toaster is
 * global, so the screen can hold toasts of earlier tests with their own Undo.
 */
function undoLast(rt: Awaited<ReturnType<typeof setup>>) {
  const notice = rt.notices.list().findLast((n) => n.action?.label === "Undo");
  if (!notice?.action) throw new Error("no Undo yet");
  notice.action.run();
}

/** The row's menu item, by name. */
async function pick(host: string, item: string) {
  await userEvent.click(within(rowOf(host)).getByRole("button", { name: `Actions for ${host}` }));
  await userEvent.click(await screen.findByRole("menuitem", { name: item }));
}

describe("row actions", () => {
  it("the menu offers what applies: Unblock on Blocked with a rule, Copy URL hidden for an IP-only row of kind other", async () => {
    await withRows();
    await userEvent.click(within(rowOf("ads.example.com")).getByRole("button", { name: "Actions for ads.example.com" }));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).toEqual(["Copy URL", "Unblock", "Do not decrypt this site", "Report a broken site"]);
    await userEvent.keyboard("{Escape}");
    await userEvent.click(within(rowOf("198.51.100.25")).getByRole("button", { name: "Actions for 198.51.100.25" }));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).toEqual(["Report a broken site"]);
  });

  it("Unblock writes nothing until the preview is confirmed, then the rule once; Undo removes it", async () => {
    const rt = await withRows();
    await pick("ads.example.com", "Unblock");
    const dialog = await screen.findByRole("dialog");
    expect(dialog.querySelector("[data-rule-preview]")).toHaveTextContent("@@||ads.example.com^");
    expect(rt.settings.get("filtering.userRules")).toEqual([]);

    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(rt.settings.get("filtering.userRules")).toEqual([]);

    await pick("ads.example.com", "Unblock");
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual(["@@||ads.example.com^"]));
    expect(await screen.findByText("Added @@||ads.example.com^ to your rules.")).toBeInTheDocument();

    undoLast(rt);
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual([]));
  });

  /** A backend whose saves fail while `disk.full` is true, or for the next `disk.failNext` saves. */
  function backendThatFills() {
    const inner = memoryBackend({ schema: 5, values: { "filtering.engine": true } });
    const disk = { full: false, failNext: 0 };
    const backend: SettingsBackend = {
      ...inner,
      save: async (doc) => {
        if (disk.failNext > 0) {
          disk.failNext--;
          throw new Error("disk full");
        }
        if (disk.full) throw new Error("disk full");
        await inner.save(doc);
      },
    };
    return { backend, disk, stored: async () => (await inner.load()) as { values: Record<string, unknown> } };
  }

  it("a save that fails and a rollback that fails too never say nothing was added: a later start may read the line", async () => {
    const { backend, disk } = backendThatFills();
    const rt = await withRows("hosts", undefined, backend);
    disk.full = true;
    await pick("ads.example.com", "Unblock");
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() =>
      expect(rt.notices.list().filter((n) => n.kind === "error").map((n) => n.text)).toEqual(["Could not save @@||ads.example.com^: disk full, and could not take it back. It may return when Sieve restarts."]),
    );
    expect(rt.notices.list().some((n) => n.kind === "success" || n.action)).toBe(false);
  });

  it("a save that fails says so, takes the line back and offers no Undo; trying again adds it", async () => {
    const { backend, disk, stored } = backendThatFills();
    const rt = await withRows("hosts", undefined, backend);
    disk.failNext = 1;
    await pick("ads.example.com", "Unblock");
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.notices.list().filter((n) => n.kind === "error").map((n) => n.text)).toEqual(["Could not save @@||ads.example.com^: disk full. Nothing was added."]));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual([]));
    expect(rt.notices.list().some((n) => n.kind === "success" || n.action)).toBe(false);

    await pick("ads.example.com", "Unblock");
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.notices.list().some((n) => n.text === "Added @@||ads.example.com^ to your rules.")).toBe(true));
    expect(rt.settings.get("filtering.userRules")).toEqual(["@@||ads.example.com^"]);
    expect((await stored()).values["filtering.userRules"]).toEqual(["@@||ads.example.com^"]);
  });

  it("an Undo whose save fails says so and the line stays, as it does on disk", async () => {
    const { backend, disk, stored } = backendThatFills();
    const rt = await withRows("hosts", undefined, backend);
    await pick("ads.example.com", "Unblock");
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.notices.list().some((n) => n.action?.label === "Undo")).toBe(true));

    disk.full = true;
    undoLast(rt);
    await vi.waitFor(() => expect(rt.notices.list().filter((n) => n.kind === "error").map((n) => n.text)).toEqual(["Could not undo: disk full. @@||ads.example.com^ stays."]));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual(["@@||ads.example.com^"]));
    expect((await stored()).values["filtering.userRules"]).toEqual(["@@||ads.example.com^"]);
  });

  it("from the details sheet: Cancel goes back to the sheet; Add it leaves no modal over the toast", async () => {
    const rt = await withRows();
    await userEvent.click(within(rowOf("ads.example.com")).getByRole("button", { name: /^ads\.example\.com,/ }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Unblock" }));
    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(within(await screen.findByRole("dialog")).getByRole("button", { name: "Unblock" })).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Unblock" }));
    await userEvent.click(await screen.findByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual(["@@||ads.example.com^"]));
    await vi.waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(await screen.findByRole("button", { name: "Undo" })).toBeInTheDocument();
  });

  it.each([
    ["cdn.example.com", "an exception rule lets it through"],
    ["tracker.example.org", "its app is off"],
  ])("no Block on %s: %s, so a block rule would change nothing", async (host) => {
    await withRows();
    await userEvent.click(within(rowOf(host)).getByRole("button", { name: `Actions for ${host}` }));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).toEqual(["Copy URL", "Do not decrypt this site", "Report a broken site"]);
  });

  it.each([
    ["Unblock", "ads.example.com", "filtering.userRules", "@@||ads.example.com^", "@@||ads.example.com^ is already in your rules."],
    ["Do not decrypt this site", "shop.example.net", "filtering.exclusions", "shop.example.net", "shop.example.net is already in the sites not decrypted."],
  ] as const)("%s of a line already there says so and offers no Undo: the line stays", async (item, host, key, line, said) => {
    const rt = await withRows("hosts", { schema: 5, values: { "filtering.engine": true, [key]: [line] } });
    const pushed = vi.spyOn(rt.notices, "push");
    await pick(host, item);
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(pushed.mock.calls.map(([n]) => n.text)).toContain(said));
    expect(pushed.mock.calls.filter(([n]) => n.action)).toEqual([]);
    expect(rt.settings.get(key)).toEqual([line]);
  });

  it("the same action twice: the second adds nothing and no second Undo", async () => {
    const rt = await withRows();
    // Spied, not read from the bus: a toast leaves it when it expires.
    const pushed = vi.spyOn(rt.notices, "push");
    for (let i = 0; i < 2; i++) {
      await pick("ads.example.com", "Unblock");
      await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Add it" }));
      await vi.waitFor(() => expect(pushed).toHaveBeenCalledTimes(i + 1));
    }
    expect(pushed.mock.calls[1][0].text).toBe("@@||ads.example.com^ is already in your rules.");
    expect(rt.settings.get("filtering.userRules")).toEqual(["@@||ads.example.com^"]);
    expect(pushed.mock.calls.filter(([n]) => n.action)).toHaveLength(1);
  });

  it("an IPv6 row: Block previews the bracketed rule, Copy URL copies a valid URL", async () => {
    const rt = await setup("missing");
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: [ipRow("2001:db8::1", { kind: "passed", reason: "no_rule" })] }));
    await pick("2001:db8::1", "Block");
    const dialog = await screen.findByRole("dialog");
    expect(dialog.querySelector("[data-rule-preview]")).toHaveTextContent("||[2001:db8::1]^");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await pick("2001:db8::1", "Copy URL");
    await vi.waitFor(() => expect(clipboard).toHaveBeenCalledWith("https://[2001:db8::1]/"));
  });

  it.each(["203.0.113.9", "2001:db8::1"])("Report from a row known only by the address %s: the URL starts empty, the report holds no address", async (host) => {
    const rt = await setup("missing");
    act(() => rt.store.setLog({ ...EMPTY_LOG, rows: [ipRow(host, { kind: "blocked" })] }));
    await pick(host, "Report a broken site");
    expect(await screen.findByRole<HTMLInputElement>("textbox", { name: "Page URL" })).toHaveValue("");
    const report = screen.getByRole<HTMLTextAreaElement>("textbox", { name: "The report" }).value;
    expect(report).toContain("Page URL: not known");
    expect(report).not.toContain(host);
  });

  it("Block the same way", async () => {
    const rt = await withRows();
    await pick("shop.example.net", "Block");
    expect((await screen.findByRole("dialog")).querySelector("[data-rule-preview]")).toHaveTextContent("||shop.example.net^");
    expect(rt.settings.get("filtering.userRules")).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual(["||shop.example.net^"]));
    await vi.waitFor(() => undoLast(rt));
    await vi.waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual([]));
  });

  it("Do not decrypt the same way, into the exclusions", async () => {
    const rt = await withRows();
    await pick("shop.example.net", "Do not decrypt this site");
    expect((await screen.findByRole("dialog")).querySelector("[data-rule-preview]")).toHaveTextContent("shop.example.net");
    expect(rt.settings.get("filtering.exclusions")).toEqual([]);
    await userEvent.click(screen.getByRole("button", { name: "Add it" }));
    await vi.waitFor(() => expect(rt.settings.get("filtering.exclusions")).toEqual(["shop.example.net"]));
    expect(rt.settings.get("filtering.userRules")).toEqual([]);
    await vi.waitFor(() => undoLast(rt));
    await vi.waitFor(() => expect(rt.settings.get("filtering.exclusions")).toEqual([]));
  });

  it("Copy URL writes the row's URL to the clipboard", async () => {
    await withRows();
    await pick("ads.example.com", "Copy URL");
    await vi.waitFor(() => expect(clipboard).toHaveBeenCalledWith("https://ads.example.com/"));
    expect(await screen.findByText("URL copied")).toBeInTheDocument();
  });

  it("Copy URL refused by the clipboard says so", async () => {
    await withRows();
    clipboard.mockRejectedValueOnce(new Error("denied"));
    await pick("ads.example.com", "Copy URL");
    expect(await screen.findByText(/Could not copy/)).toBeInTheDocument();
  });

  it("Copy URL with no clipboard at all says so, not that it copied", async () => {
    const rt = await withRows();
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    await pick("ads.example.com", "Copy URL");
    await vi.waitFor(() => expect(rt.notices.list().map((n) => n.kind)).toContain("error"));
    expect(rt.notices.list().map((n) => n.text)).not.toContain("URL copied");
  });
});
