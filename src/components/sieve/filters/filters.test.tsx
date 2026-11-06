import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NoticeToaster } from "@/components/sieve/shell/notice-toaster";
import { MAX_POLICY_BYTES } from "@/core/settings/registry";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { MOCK_LISTS_ERROR, createMockFilterLists, type FilterListScenario } from "@/data/filter-lists-mock";
import type { FilterListSource } from "@/data/filter-lists-source";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import { parseFilterCatalogue, type EnginePolicy } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { FiltersScreen, NOT_APPLIED_TEXT } from "./filters-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/filters/" }));
vi.setConfig({ testTimeout: 20_000 });

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const undo of cleanups.splice(0)) undo();
});

async function setup(lists: FilterListScenario | FilterListSource = "pending", stored?: unknown, engine?: EngineSource) {
  const filterLists = typeof lists === "string" ? createMockFilterLists(lists) : lists;
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend(stored), filterLists, engine });
  const unbind = runtime.engineController.bind();
  cleanups.push(unbind);
  render(
    <SieveProvider runtime={runtime}>
      <FiltersScreen />
      <NoticeToaster />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
    await new Promise((r) => setTimeout(r, 0));
  });
  return runtime;
}

const answering = (raw: unknown): FilterListSource => ({ kind: "mock", catalogue: async () => parseFilterCatalogue(raw), checkRules: async () => [] });
const list = (id: string) => document.querySelector<HTMLElement>(`[data-list="${id}"]`)!;
const group = (id: string) => document.querySelector<HTMLElement>(`[data-list-group="${id}"]`)!;
const pending = () => document.querySelector("[data-filters-pending]");
const reportedId = fixture.examples.loaded.lists.find((l) => l.report?.skipped)!.id;

/** The engine's facts in the store, then whatever they caused settled. */
const settled = () => act(async () => {
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
});

describe("the engine's report", () => {
  it("each list shows the applied and skipped counts engine_lists answers, with the parser's reasons", async () => {
    const rt = await setup("pending", undefined, createMockEngine("filtering"));
    await settled();
    const { lists } = await rt.engine.lists();
    const row = lists.find((l) => l.network > 0)!;
    expect(list(row.id)).toHaveTextContent(`${row.network.toLocaleString("en-US")} applied, ${row.skipped} skipped`);
    expect(pending(), "a list is in force").toBeNull();
    const fetchedNothing = lists.find((l) => l.network === 0)!;
    expect(list(fetchedNothing.id)).toHaveTextContent("Not loaded yet");
  });

  it("an engine that cannot answer leaves what the seam gave, never an error", async () => {
    await setup("pending", undefined, createMockEngine("missing"));
    await settled();
    expect(pending()).toHaveTextContent(NOT_APPLIED_TEXT);
    const failing = { ...createMockEngine("filtering"), lists: () => Promise.reject(new Error("the pipe broke")) };
    cleanup();
    await setup("loaded", undefined, failing);
    await settled();
    expect(list(reportedId)).toHaveTextContent("applied");
  });
});

describe("one store for the user's rules", () => {
  it("the blocklist writes the key the engine reads", async () => {
    const rt = await setup();
    await userEvent.type(screen.getByRole("textbox", { name: "Add to Blocklist" }), "https://Tracker.Example/x");
    await userEvent.click(within(screen.getByRole("textbox", { name: "Add to Blocklist" }).closest("form")!).getByRole("button", { name: "Add" }));
    await waitFor(() => expect(rt.settings.get("filtering.blockedDomains")).toEqual(["tracker.example"]));
    await userEvent.click(screen.getByRole("button", { name: "Remove tracker.example" }));
    await waitFor(() => expect(rt.settings.get("filtering.blockedDomains")).toEqual([]));
  });

  it("what the editors write reaches the engine in the next policy", async () => {
    const sent: EnginePolicy[] = [];
    const mock = createMockEngine("idle");
    const rt = await setup("pending", undefined, { ...mock, setPolicy: (p) => (sent.push(p), mock.setPolicy(p)) });
    await settled();
    await act(async () => {
      await rt.settings.set("filtering.userRules", ["||a.example^"]);
      await rt.settings.set("filtering.allowedDomains", ["b.example"]);
    });
    await settled();
    expect(sent.at(-1)).toMatchObject({ user_rules: ["||a.example^"], domain_lists: [{ kind: "allow", entries: ["b.example"], enabled: true }] });
  });
});

describe("the list catalogue", () => {
  it("pending says Not loaded yet and never shows a 0, and says nothing is applied", async () => {
    await setup("pending");
    const counts = [...document.querySelectorAll("[data-list-count]")].map((c) => c.textContent);
    expect(counts.length).toBeGreaterThan(0);
    expect(new Set(counts)).toEqual(new Set(["Not loaded yet"]));
    expect(document.querySelector("[data-list-catalogue]")!.textContent).not.toMatch(/\b0 applied/);
    expect(pending()).toHaveTextContent(NOT_APPLIED_TEXT);
  });

  it("loaded shows the fixture's counts, the reasons in a tooltip, and the line goes", async () => {
    await setup("loaded");
    expect(pending()).toBeNull();
    const row = within(list(reportedId));
    const count = row.getByText("48,211 applied, 12 skipped");
    expect(screen.queryByRole("tooltip")).toBeNull();
    expect(count).not.toHaveAttribute("title");
    fireEvent.pointerEnter(count, { clientX: 10, clientY: 10 });
    expect(screen.getByRole("tooltip")).toHaveTextContent("network filter error: unrecognised option");
    fireEvent.pointerLeave(count);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("error shows the Card's error state; empty its empty state", async () => {
    await setup("error");
    expect(screen.getByRole("alert")).toHaveTextContent(MOCK_LISTS_ERROR);
  });

  it("empty says so", async () => {
    await setup("empty");
    expect(screen.getByText("No filter lists yet")).toBeInTheDocument();
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["old schema", { v: 0, lists: [] }],
    ["newer schema", { v: 2, lists: [] }],
    ["no lists", { v: 1 }],
  ])("%s renders an error, not a crash", async (_name, raw) => {
    await setup(answering(raw));
    expect(screen.getByRole("alert")).toHaveTextContent("Snapshot protocol");
    expect(screen.getByRole("heading", { name: "Filters" })).toBeInTheDocument();
  });

  it("malformed rows are dropped and counted, partial rows render", async () => {
    const good = fixture.examples.pending.lists[0];
    await setup(answering({ v: 1, lists: [good, null, { id: "broken" }, { id: "partial", title: "Partial list", default: "off" }] }));
    expect(list(good.id)).toBeInTheDocument();
    expect(list("partial")).toHaveTextContent("Not loaded yet");
    expect(document.querySelector("[data-lists-dropped]")).toHaveTextContent("2 lists could not be read");
  });

  it("a selection with unknown ids and an old settings document render", async () => {
    const rt = await setup("pending", { schema: 1, values: { "filters.lists": { "from-the-future": "on" }, "filtering.userRules": ["##+js(trusted-x)"], "filtering.allowedDomains": "nope" } });
    expect(screen.getByRole("textbox", { name: "User rules" })).toHaveValue("");
    await userEvent.click(within(list("adguard-cookies")).getByRole("switch"));
    expect(rt.settings.get("filters.lists")).toEqual({ "from-the-future": "on", "adguard-cookies": "on" });
  });
});

describe("list switches", () => {
  it("a list's switch writes only a difference; a gated list cannot be turned on", async () => {
    const rt = await setup();
    const on = within(list("adguard-base")).getByRole("switch");
    expect(on).toBeChecked();
    await userEvent.click(on);
    expect(rt.settings.get("filters.lists")).toEqual({ "adguard-base": "off" });
    await userEvent.click(on);
    expect(rt.settings.get("filters.lists")).toEqual({});
    const gated = within(list("ubo-filters"));
    expect(gated.getByRole("switch")).toBeDisabled();
    expect(gated.getByRole("switch")).not.toBeChecked();
    expect(gated.getByText("Waiting on testing")).toBeInTheDocument();
  });

  it("the group switch changes its lists and its state is derived", async () => {
    const rt = await setup();
    const annoyances = group("annoyances");
    expect(annoyances).toHaveTextContent("0 of 5 on");
    await userEvent.click(within(annoyances).getByRole("switch", { name: "All annoyances lists" }));
    expect(annoyances).toHaveTextContent("5 of 5 on");
    expect(Object.keys(rt.settings.get("filters.lists"))).toHaveLength(5);
    await userEvent.click(within(list("adguard-cookies")).getByRole("switch"));
    expect(annoyances).toHaveTextContent("4 of 5 on");
    expect(within(annoyances).getByRole("switch", { name: "All annoyances lists" })).not.toBeChecked();
  });
});

describe("user rules", () => {
  const editor = () => screen.getByRole("textbox", { name: "User rules" });
  const save = () => screen.getByRole("button", { name: "Save rules" });

  it("a check that fails is said in the rule problems, nothing is saved, and the next edit clears it", async () => {
    const rejecting: FilterListSource = { ...createMockFilterLists("pending"), checkRules: () => Promise.reject(new Error("task 7 panicked")) };
    const rt = await setup(rejecting);
    fireEvent.change(editor(), { target: { value: "||a.example^" } });
    await userEvent.click(save());
    const problems = await screen.findByRole("list", { name: "Rule problems" });
    expect(within(problems).getByRole("alert")).toHaveTextContent("These rules were not saved: Sieve could not check or store them.");
    expect(within(problems).getByRole("alert")).toHaveTextContent("task 7 panicked");
    expect(rt.settings.get("filtering.userRules")).toEqual([]);
    expect(editor()).toHaveValue("||a.example^");
    fireEvent.change(editor(), { target: { value: "||b.example^" } });
    expect(screen.queryByRole("list", { name: "Rule problems" })).toBeNull();
  });

  it("a list the engine could not hold is refused with the reason, wherever it is added to", async () => {
    // In a setting no row lists, so the budget is what is under test and not jsdom.
    const rt = await setup("pending", { schema: 5, values: { "filtering.exclusions": ["x".repeat(MAX_POLICY_BYTES)] } });
    fireEvent.change(editor(), { target: { value: "||a-rule-that-is-one-too-many.example^" } });
    await userEvent.click(save());
    expect(within(await screen.findByRole("list", { name: "Rule problems" })).getByRole("alert")).toHaveTextContent("the engine can hold, so this was not saved");
    expect(rt.settings.get("filtering.userRules")).toEqual([]);

    await userEvent.type(screen.getByRole("textbox", { name: "Add to Allowlist" }), "one-too-many.example{Enter}");
    await waitFor(() => expect(rt.notices.list().map((n) => n.text)).toContainEqual(expect.stringContaining("the engine can hold, so this was not saved")));
    expect(rt.settings.get("filtering.allowedDomains")).toEqual([]);
  });

  it("an error names its line and Save is disabled; fixing it enables Save, and Save stores the lines", async () => {
    const rt = await setup();
    fireEvent.change(editor(), { target: { value: "! note\n\n||bad rule^" } });
    expect(screen.getByRole("alert")).toHaveTextContent("Line 3: A network rule cannot hold a space.");
    expect(save()).toBeDisabled();
    fireEvent.change(editor(), { target: { value: "! note\n\n||good.example^" } });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(save()).toBeEnabled();
    await userEvent.click(save());
    expect(rt.settings.get("filtering.userRules")).toEqual(["! note", "||good.example^"]);
    expect(editor()).toHaveValue("! note\n||good.example^");
    expect(save()).toBeDisabled();
  });

  it("a hint helps without stopping the save", async () => {
    await setup();
    fireEvent.change(editor(), { target: { value: "example.com" } });
    expect(screen.getByText(/Did you mean \|\|example\.com\^\?/)).toBeInTheDocument();
    expect(save()).toBeEnabled();
  });

  it("what the engine's parser refuses is said on its editor line, in words and its own, and nothing is saved", async () => {
    const source: FilterListSource = { ...createMockFilterLists(), checkRules: async () => [{ line: 2, reason: "network filter error: unrecognised option" }] };
    const rt = await setup(source);
    fireEvent.change(editor(), { target: { value: "! note\n\n||a.example^$nope" } });
    await userEvent.click(save());
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Line 3: This rule has a $ option Sieve does not know.");
    expect(alert).toHaveTextContent("network filter error: unrecognised option");
    expect(rt.settings.get("filtering.userRules")).toEqual([]);
  });

  it("Block a site appends its rule to the editor, once, and refuses junk with a sentence", async () => {
    await setup("pending", { schema: 4, values: { "filtering.userRules": ["||a.example^"] } });
    const site = screen.getByRole("textbox", { name: "Block a site" });
    await userEvent.type(site, "https://Ads.Example.com/x{Enter}");
    expect(editor()).toHaveValue("||a.example^\n||ads.example.com^");
    await userEvent.type(site, "ads.example.com{Enter}");
    expect(editor()).toHaveValue("||a.example^\n||ads.example.com^");
    await userEvent.type(site, "localhost{Enter}");
    expect(screen.getByRole("alert")).toHaveTextContent("needs a dot");
  });
});

describe("allowlist", () => {
  const add = (text: string) => userEvent.type(screen.getByRole("textbox", { name: "Add to Allowlist" }), `${text}{Enter}`);

  it("adds a normalized host; a duplicate is absorbed; a bad one is refused with a sentence", async () => {
    const rt = await setup();
    await add("https://WWW.Example.com/a?b");
    expect(rt.settings.get("filtering.allowedDomains")).toEqual(["www.example.com"]);
    await add("www.example.com");
    expect(rt.settings.get("filtering.allowedDomains")).toEqual(["www.example.com"]);
    await add("1.2.3.4");
    expect(screen.getByRole("alert")).toHaveTextContent("IP address");
  });

  it("removal gives an undo toast and undo restores", async () => {
    const rt = await setup("pending", { schema: 4, values: { "filtering.allowedDomains": ["a.example", "b.example"] } });
    await userEvent.click(screen.getByRole("button", { name: "Remove a.example" }));
    expect(rt.settings.get("filtering.allowedDomains")).toEqual(["b.example"]);
    await userEvent.click(await screen.findByRole("button", { name: "Undo" }));
    expect(rt.settings.get("filtering.allowedDomains")).toEqual(["b.example", "a.example"]);
  });
});
