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

describe("what the screen says is in force", () => {
  /** The switch on, so the mock engine stays in the example it started in. */
  const ROUTING = { schema: 5, values: { "filtering.engine": true } };
  /** The next probe's facts, unchanged: a new answer with the same small facts. */
  const nextProbe = (rt: Awaited<ReturnType<typeof setup>>) =>
    act(async () => {
      const e = rt.store.getState().engine;
      rt.store.setEngine({ ...e, probe: { ...e.probe! } });
      await new Promise((r) => setTimeout(r, 0));
    });

  it("a failed report read never says nothing is in force while the probe reports rules applied, and is asked again at the next probe", async () => {
    const mock = createMockEngine("hosts");
    const pipe = { broken: true };
    const lists = vi.fn(() => (pipe.broken ? Promise.reject(new Error("the pipe broke")) : mock.lists()));
    const rt = await setup("pending", ROUTING, { ...mock, lists });
    await settled();
    expect(lists).toHaveBeenCalled();
    expect(pending(), "the engine reports rules applied").toBeNull();
    const row = (await mock.lists()).lists.find((l) => l.network > 0)!;
    expect(list(row.id)).toHaveTextContent("Not loaded yet");

    pipe.broken = false;
    const failed = lists.mock.calls.length;
    await nextProbe(rt);
    await settled();
    expect(lists).toHaveBeenCalledTimes(failed + 1);
    expect(list(row.id)).toHaveTextContent(`${row.network.toLocaleString("en-US")} applied`);
    await nextProbe(rt);
    await settled();
    expect(lists, "answered: not read on the probe's cadence").toHaveBeenCalledTimes(failed + 1);
  });

  it("says nothing before the first report arrives, or while the catalogue is out", async () => {
    const mock = createMockEngine("hosts");
    await setup("pending", ROUTING, { ...mock, lists: () => new Promise(() => {}) });
    await settled();
    expect(pending()).toBeNull();
    cleanup();
    await setup("error", undefined, createMockEngine("idle"));
    await settled();
    expect(pending()).toBeNull();
  });

  it("says nothing while the engine's state cannot be read", async () => {
    await setup("pending", undefined, createMockEngine("error"));
    await settled();
    expect(pending()).toBeNull();
  });

  it("an engine that answers with no list applied, and no engine at all, do say it", async () => {
    const idle = createMockEngine("idle");
    const empty = await idle.lists();
    await setup("pending", undefined, { ...idle, lists: async () => ({ ...empty, lists: [] }) });
    await settled();
    expect(pending()).toHaveTextContent(NOT_APPLIED_TEXT);
    cleanup();
    await setup("pending", undefined, createMockEngine("missing"));
    await settled();
    expect(pending()).toHaveTextContent(NOT_APPLIED_TEXT);
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
    expect(gated.getByText(/Waiting on testing/)).toBeInTheDocument();
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

  it("a save in flight holds Save, so an older save can never land over a newer one", async () => {
    const release: (() => void)[] = [];
    const source: FilterListSource = {
      ...createMockFilterLists("pending"),
      checkRules: () => new Promise((r) => release.push(() => r([]))),
    };
    const rt = await setup(source);
    fireEvent.change(editor(), { target: { value: "||older.example^" } });
    await userEvent.click(save());
    fireEvent.change(editor(), { target: { value: "||newer.example^" } });
    expect(save(), "the older check has not answered").toBeDisabled();
    await act(async () => {
      release.shift()!();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(rt.settings.get("filtering.userRules")).toEqual(["||older.example^"]);
    expect(editor(), "what was typed since stays").toHaveValue("||newer.example^");
    await userEvent.click(save());
    await act(async () => {
      release.shift()!();
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(rt.settings.get("filtering.userRules")).toEqual(["||newer.example^"]);
    expect(save()).toBeDisabled();
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

  const site = () => screen.getByRole("textbox", { name: "Site" });

  it("the rule form says what it will do, saves its rule at once, once, and refuses junk with a sentence", async () => {
    const rt = await setup("pending", { schema: 4, values: { "filtering.userRules": ["||a.example^"] } });
    await userEvent.type(site(), "https://Ads.Example.com/x");
    expect(document.querySelector("[data-rule-meaning]")).toHaveTextContent("Blocks ads.example.com and every address under it");
    await userEvent.type(screen.getByRole("textbox", { name: "Note (optional)" }), "Pop-ups");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
    await waitFor(() => expect(rt.settings.get("filtering.userRules")).toEqual(["||a.example^", "! Pop-ups", "||ads.example.com^"]));
    expect(editor()).toHaveValue("||a.example^\n! Pop-ups\n||ads.example.com^");
    expect(screen.getByRole("status")).toHaveTextContent("Rule added.");
    await userEvent.type(site(), "ads.example.com{Enter}");
    expect(screen.getByRole("status")).toHaveTextContent("already there");
    expect(rt.settings.get("filtering.userRules")).toHaveLength(3);
    await userEvent.type(site(), "localhost{Enter}");
    expect(screen.getByRole("alert")).toHaveTextContent("needs a dot");
  });

  it("an allow rule for one site alone writes the exact rules, and joins unsaved edits instead of saving them", async () => {
    const rt = await setup();
    fireEvent.change(editor(), { target: { value: "||typed.example^" } });
    await userEvent.click(screen.getByRole("radio", { name: "Allow" }));
    await userEvent.click(screen.getByRole("switch", { name: "Include subdomains" }));
    await userEvent.type(site(), "shop.example");
    expect(document.querySelector("[data-rule-meaning]")).toHaveTextContent("Lets shop.example through, but not its subdomains");
    await userEvent.click(screen.getByRole("button", { name: "Add rule" }));
    expect(editor()).toHaveValue("||typed.example^\n@@|https://shop.example^\n@@|http://shop.example^");
    expect(screen.getByRole("status")).toHaveTextContent("Save them to apply it");
    expect(rt.settings.get("filtering.userRules"), "nothing typed was saved behind the person's back").toEqual([]);
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

const radio = (name: RegExp) => within(screen.getByRole("radiogroup", { name: "Protection level" })).getByRole("radio", { name });

describe("protection level", () => {
  it("a person who changed nothing is on Balanced, the recommended level, and each level is said in a sentence", async () => {
    await setup();
    expect(radio(/^Balanced/)).toHaveAttribute("aria-checked", "true");
    expect(radio(/^Balanced/)).toHaveTextContent("Recommended");
    expect(radio(/^Strict/)).toHaveTextContent("Some sites may not work");
    expect(radio(/^Minimal/)).toHaveTextContent("Blocks ads only");
    expect(document.querySelector("[data-profile-custom]")).toBeNull();
  });

  it("picking Strict turns on exactly its lists, says so with an Undo, and the Undo restores Balanced", async () => {
    const rt = await setup();
    await userEvent.click(radio(/^Strict/));
    expect(radio(/^Strict/)).toHaveAttribute("aria-checked", "true");
    expect(group("annoyances")).toHaveTextContent("5 of 5 on");
    expect(list("adguard-german"), "a language list is not part of a level: still off, still folded away").toBeNull();
    await userEvent.click(await screen.findByRole("button", { name: "Undo" }));
    await waitFor(() => expect(rt.settings.get("filters.lists")).toEqual({}));
    expect(radio(/^Balanced/)).toHaveAttribute("aria-checked", "true");
  });

  it("changing any list under it shows Custom by itself; Back to recommended restores the lists in one action, a language kept", async () => {
    const rt = await setup();
    await userEvent.click(screen.getByRole("button", { name: /Show \d+ languages/ }));
    await userEvent.click(within(list("adguard-german")).getByRole("switch"));
    expect(radio(/^Balanced/), "a language list keeps the level").toHaveAttribute("aria-checked", "true");
    await userEvent.click(within(list("adguard-cookies")).getByRole("switch"));
    expect(document.querySelector("[data-profile-custom]")).toHaveTextContent("Custom");
    for (const name of [/^Balanced/, /^Strict/, /^Minimal/]) expect(radio(name)).toHaveAttribute("aria-checked", "false");
    // Said where the person is, far below the level, with the way back in the notice too.
    expect(rt.notices.list().map((n) => n.text)).toContain("Protection level is now Custom: Balanced with your change");
    await userEvent.click(within(document.querySelector<HTMLElement>("[data-profile-custom]")!).getByRole("button", { name: "Back to recommended" }));
    await waitFor(() => expect(rt.settings.get("filters.lists")).toEqual({ "adguard-german": "on" }));
    expect(radio(/^Balanced/)).toHaveAttribute("aria-checked", "true");
  });

  it("arrows move along the levels as in any radio group", async () => {
    const rt = await setup();
    radio(/^Balanced/).focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(radio(/^Strict/)).toHaveFocus();
    expect(radio(/^Strict/)).toHaveAttribute("aria-checked", "true");
    expect(Object.keys(rt.settings.get("filters.lists")).length).toBeGreaterThan(0);
  });

  it("a catalogue that cannot be read is said once, by the lists, and no level can be picked", async () => {
    await setup("error");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(document.querySelector("[data-protection-level]")).toHaveTextContent("none can be picked now");
    expect(screen.queryByRole("radio", { name: /^Balanced/ })).toBeNull();
  });
});

describe("languages", () => {
  it("suggests the list of the computer's language first, and keeps the other languages one click away", async () => {
    const languages = vi.spyOn(navigator, "languages", "get").mockReturnValue(["de-DE", "en-US"]);
    cleanups.push(() => languages.mockRestore());
    await setup();
    expect(list("adguard-german")).toHaveTextContent("Suggested for your language");
    expect(list("adguard-french")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Show 8 more languages/ }));
    expect(list("adguard-french")).toBeInTheDocument();
  });
});

describe("a list's menu", () => {
  it("shows a list's rules from the engine's copy, searchable, with how many there are", async () => {
    await setup("loaded", { schema: 5, values: { "filtering.engine": true } }, createMockEngine("filtering"));
    await settled();
    await userEvent.click(within(list("adguard-base")).getByRole("button", { name: /Actions for/ }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "View rules" }));
    const dialog = await screen.findByRole("dialog");
    await waitFor(() => expect(dialog.querySelector("[data-rules-caption]")).toHaveTextContent("420 rules. The first 200 are shown; search to find others."));
    expect(within(dialog).getByRole("list", { name: /Rules of/ }).children).toHaveLength(200);
    await userEvent.type(within(dialog).getByRole("searchbox"), "pixel1");
    await waitFor(() => expect(dialog.querySelector("[data-rules-caption]")).toHaveTextContent(/^\d+ of 420 rules match\.$/));
    expect(dialog.querySelector("[data-rules-caption]")!.textContent, "the caption is the search's own answer").not.toMatch(/^420 of/);
    for (const li of within(dialog).getByRole("list", { name: /Rules of/ }).children) expect(li.textContent).toContain("pixel1");
  });

  it("with no engine, View rules and Update now are disabled and the menu says why", async () => {
    await setup("loaded", undefined, createMockEngine("missing"));
    await settled();
    await userEvent.click(within(list("adguard-base")).getByRole("button", { name: /Actions for/ }));
    const menu = await screen.findByRole("menu");
    expect(within(menu).getByRole("menuitem", { name: "View rules" })).toHaveAttribute("aria-disabled", "true");
    expect(menu).toHaveTextContent("Sieve's engine is not running");
  });

  it("Update now asks the engine for that one list", async () => {
    const mock = createMockEngine("filtering");
    const asked: string[] = [];
    await setup("loaded", { schema: 5, values: { "filtering.engine": true } }, { ...mock, listRefresh: (id) => (asked.push(id), mock.listRefresh(id)) });
    await settled();
    await userEvent.click(within(list("adguard-base")).getByRole("button", { name: /Actions for/ }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Update now" }));
    expect(asked).toEqual(["adguard-base"]);
  });
});

describe("your own lists", () => {
  const address = () => screen.getByRole("textbox", { name: "List address" });
  const own = (id: string) => document.querySelector<HTMLElement>(`[data-own-list="${id}"]`);

  it("adds a list by address, named after its file, and refuses an address the engine would not download", async () => {
    const rt = await setup();
    await userEvent.type(address(), "http://lists.example/mine.txt{Enter}");
    expect(screen.getByRole("alert")).toHaveTextContent("https only");
    await userEvent.clear(address());
    await userEvent.type(address(), "lists.example/My%20blocklist.txt{Enter}");
    await waitFor(() => expect(rt.settings.get("filters.custom")).toHaveLength(1));
    const [added] = rt.settings.get("filters.custom");
    expect(added).toMatchObject({ title: "My blocklist", url: "https://lists.example/My%20blocklist.txt", enabled: true });
    expect(added.id).toMatch(/^custom-[a-z0-9]{8}$/);
    expect(own(added.id)).toHaveTextContent("lists.example");
    expect(own(added.id), "no engine report: nothing is claimed").toHaveTextContent("Not loaded yet");
    await userEvent.type(address(), "https://lists.example/My%20blocklist.txt{Enter}");
    expect(screen.getByRole("alert")).toHaveTextContent("already one of yours");
  });

  it("shows what the engine says of each: counts and when, or why it refused, in words and its own", async () => {
    const values = {
      "filtering.engine": true,
      "filters.custom": [
        { id: "custom-a1", title: "Good", url: "https://lists.example/good.txt", enabled: true },
        { id: "custom-b2", title: "Portal", url: "https://lists.example/broken.txt", enabled: true },
      ],
    };
    await setup("pending", { schema: 5, values }, createMockEngine("filtering"));
    await settled();
    await waitFor(() => expect(own("custom-a1")).toHaveTextContent("1,204 applied, 0 skipped"));
    expect(own("custom-a1")).toHaveTextContent(/Updated/);
    expect(own("custom-b2")).toHaveTextContent("The address gave a web page, not a filter list");
    expect(own("custom-b2")).toHaveTextContent("an HTML page, not a filter list");
  });

  it("imports a file through the engine; a closed picker adds nothing; a refused file says why", async () => {
    const rt = await setup("pending", { schema: 5, values: { "filtering.engine": true } }, createMockEngine("filtering"));
    await settled();
    await userEvent.click(screen.getByRole("button", { name: "Import a file" }));
    await waitFor(() => expect(rt.settings.get("filters.custom")).toEqual([expect.objectContaining({ title: "My blocklist", url: null, enabled: true })]));
    cleanup();
    const closed = await setup("pending", { schema: 5, values: { "filtering.engine": true } }, createMockEngine("filtering", { importAnswer: "cancel" }));
    await settled();
    await userEvent.click(screen.getByRole("button", { name: "Import a file" }));
    expect(closed.settings.get("filters.custom")).toEqual([]);
    expect(screen.queryByRole("alert")).toBeNull();
    cleanup();
    const refused = await setup("pending", { schema: 5, values: { "filtering.engine": true } }, createMockEngine("filtering", { importAnswer: "refused" }));
    await settled();
    await userEvent.click(screen.getByRole("button", { name: "Import a file" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("an HTML page");
    expect(refused.settings.get("filters.custom")).toEqual([]);
  });

  it("with no engine, importing is disabled with the reason, and a list by address can still be added", async () => {
    const rt = await setup("pending", undefined, createMockEngine("missing"));
    await settled();
    expect(screen.getByRole("button", { name: "Import a file" })).toBeDisabled();
    expect(document.querySelector("[data-own-lists]")).toHaveTextContent("Importing a file needs the engine");
    await userEvent.type(address(), "https://lists.example/a.txt{Enter}");
    await waitFor(() => expect(rt.settings.get("filters.custom")).toHaveLength(1));
  });

  it("a list is turned off and on by its switch, and removed with an Undo", async () => {
    const values = { "filters.custom": [{ id: "custom-a1", title: "Mine", url: "https://lists.example/a.txt", enabled: true }] };
    const rt = await setup("pending", { schema: 5, values });
    await userEvent.click(within(own("custom-a1")!).getByRole("switch", { name: "Mine" }));
    expect(rt.settings.get("filters.custom")[0].enabled).toBe(false);
    await userEvent.click(within(own("custom-a1")!).getByRole("button", { name: "Actions for Mine" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Remove" }));
    await waitFor(() => expect(rt.settings.get("filters.custom")).toEqual([]));
    const toast = (await screen.findAllByRole("listitem")).find((li) => li.textContent?.includes("Removed Mine"))!;
    await userEvent.click(within(toast).getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(rt.settings.get("filters.custom")).toHaveLength(1));
  });

  it("a stored list that is broken or from an older build reads as none, never a crash", async () => {
    await setup("pending", { schema: 5, values: { "filters.custom": [{ id: "custom-a1", title: "x" }, "junk"] } });
    expect(document.querySelector("[data-own-lists]")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Your own lists" })).toBeNull();
  });
});

describe("tracking protection", () => {
  it("is at Standard, the recommended level, every option locked with the reason once, and nothing can change it", async () => {
    await setup();
    const block = document.querySelector<HTMLElement>("[data-tracking]")!;
    expect(within(block).getByRole("radio", { name: /^Standard/ })).toHaveAttribute("aria-checked", "true");
    expect(within(block).getByRole("radio", { name: /^Standard/ })).toBeDisabled();
    expect(block.querySelectorAll("[data-lock]")).toHaveLength(1);
    expect(block.querySelector("[data-tracking-locked]")).toHaveTextContent("which this version of Sieve does not offer yet");
    expect(block.querySelector("[data-tracking-locked]")).toHaveTextContent("None of these is in effect yet");
    for (const s of within(block).getAllByRole("switch")) expect(s).toBeDisabled();
  });

  it("says what each option off at Standard can break", async () => {
    await setup();
    const webRtc = document.querySelector<HTMLElement>('[data-tracking-option="tracking.webRtc"]')!;
    expect(webRtc).toHaveTextContent("Can break: Video calls");
    expect(within(webRtc).getByRole("switch")).not.toBeChecked();
  });

  it("a stored custom choice reads Custom and stays a wish: never sent while locked", async () => {
    const sent: EnginePolicy[] = [];
    const mock = createMockEngine("idle");
    await setup("pending", { schema: 5, values: { "filtering.engine": true, "tracking.webRtc": true } }, { ...mock, setPolicy: (p) => (sent.push(p), mock.setPolicy(p)) });
    await settled();
    expect(document.querySelector("[data-tracking-custom]")).toHaveTextContent("Your own choice");
    expect(sent.length).toBeGreaterThan(0);
    for (const p of sent) expect(p.tracking ?? []).toEqual([]);
  });
});
