import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ENGINE_SWITCH, HTTPS_SWITCH, type EngineSlice } from "@/core/engine";
import { EXCLUSIONS_SHOWN, FLOOR_LINE, NOT_IN_FORCE_LINE } from "@/core/exclusions";
import { createMockEngine } from "@/data/engine-mock";
import type { EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import type { ExclusionRow } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { ExclusionsGroup } from "./exclusions-group";

vi.setConfig({ testTimeout: 20_000 });

// Radix Select needs what jsdom lacks.
beforeAll(() => {
  for (const m of ["setPointerCapture", "releasePointerCapture", "scrollIntoView"] as const) {
    if (!(m in Element.prototype)) Object.defineProperty(Element.prototype, m, { value: () => {}, configurable: true });
  }
  if (!("hasPointerCapture" in Element.prototype)) Object.defineProperty(Element.prototype, "hasPointerCapture", { value: () => false, configurable: true });
});

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

async function setup(options: { engine?: EngineSource; lines?: string[]; search?: string } = {}) {
  window.history.replaceState(null, "", `/settings/${options.search ?? ""}`);
  const values = { [ENGINE_SWITCH]: false, "filtering.exclusions": options.lines ?? [] };
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values }), engine: options.engine ?? createMockEngine("idle", { heal: true }) });
  render(
    <SieveProvider runtime={runtime}>
      <ExclusionsGroup />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return { runtime, user: userEvent.setup() };
}

/** A running view with the engine's rows in. */
async function withRows(options: Parameters<typeof setup>[0] = {}) {
  const set = await setup(options);
  await screen.findByText('"pin.example"');
  return set;
}

const group = () => screen.getByRole("region", { name: "Not decrypted" });
const lines = () => [...group().querySelectorAll("[data-exclusion-row] .font-mono")].map((n) => n.textContent);
const rowOf = (line: string) => screen.getByText(line).closest("li") as HTMLElement;

/** The group reached with a shape no normalizer ever passed: the render path holds regardless. */
async function withSlice(rt: Runtime, patch: Partial<EngineSlice>) {
  act(() => rt.store.setEngine({ ...rt.store.getState().engine, ...patch }));
}

describe("Not decrypted", () => {
  it("rows with reasons in words, the app or All apps", async () => {
    await withRows({ lines: ["mine.example"] });
    expect(lines()).toEqual(["mine.example", "bank.example", '"pin.example"', '"cert.example"', '"ev.example"']);
    expect(rowOf("mine.example")).toHaveTextContent("You added this");
    expect(rowOf("mine.example")).toHaveTextContent("All apps");
    expect(rowOf("bank.example")).toHaveTextContent("Sensitive site (Sieve's list)");
    expect(rowOf('"pin.example"')).toHaveTextContent("Rejected Sieve's certificate (auto), tried again 1 time");
    expect(rowOf('"pin.example"')).toHaveTextContent("client.exe");
    expect(rowOf('"cert.example"')).toHaveTextContent("Asks for a client certificate (auto)");
    expect(rowOf('"ev.example"')).toHaveTextContent("EV certificate (auto)");
  });

  it("actions by kind: remove yours, try again on the engine's own, nothing on a list's", async () => {
    await withRows({ lines: ["mine.example"] });
    expect(within(rowOf("mine.example")).getByRole("button", { name: "Remove mine.example" })).toBeInTheDocument();
    expect(within(rowOf("bank.example")).queryByRole("button")).toBeNull();
    for (const line of ['"pin.example"', '"cert.example"', '"ev.example"']) {
      expect(within(rowOf(line)).getByRole("button", { name: `Try decrypting ${line} again` })).toBeInTheDocument();
    }
  });

  it("filter by reason: the groups come from the rows", async () => {
    const { user } = await withRows({ lines: ["mine.example"] });
    const filter = screen.getByRole("radiogroup", { name: "Filter by reason" });
    expect(within(filter).getAllByRole("radio").map((r) => r.textContent)).toEqual(["All", "Yours", "Sensitive", "Rejected", "Client certificate", "EV"]);
    await user.click(within(filter).getByRole("radio", { name: "Rejected" }));
    expect(lines()).toEqual(['"pin.example"']);
    expect(window.location.search).toBe("?exclusionsReason=pinning");
    await user.click(within(filter).getByRole("radio", { name: "All" }));
    expect(lines()).toHaveLength(5);
    expect(window.location.search).toBe("");
  });

  it("search by pattern, app and reason; no match offers the way back", async () => {
    const { user } = await withRows();
    const search = screen.getByRole("searchbox", { name: "Search sites not decrypted" });
    await user.type(search, "client.exe");
    expect(lines()).toEqual(['"pin.example"']);
    await user.clear(search);
    await user.type(search, "asks for");
    expect(lines()).toEqual(['"cert.example"']);
    await user.clear(search);
    await user.type(search, "nothing-like-this");
    expect(lines()).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Show every row" }));
    expect(lines()).toHaveLength(4);
  });

  it("add a host; the list is the setting", async () => {
    const { runtime, user } = await withRows();
    await user.type(screen.getByRole("textbox", { name: "Add a site not to decrypt" }), "https://Shop.Example/cart");
    await user.click(screen.getByRole("button", { name: "Add" }));
    await vi.waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual(["shop.example"]));
    expect(screen.getByRole<HTMLInputElement>("textbox", { name: "Add a site not to decrypt" }).value).toBe("");
    expect(rowOf("shop.example")).toHaveTextContent("You added this");
  });

  it("add a host for one running app", async () => {
    const { runtime, user } = await withRows();
    await vi.waitFor(() => expect(runtime.store.getState().snapshots.length).toBeGreaterThan(0));
    await user.click(screen.getByRole("combobox", { name: "For which app" }));
    await user.click(await screen.findByRole("option", { name: /chrome\.exe/ }));
    await user.type(screen.getByRole("textbox", { name: "Add a site not to decrypt" }), "shop.example");
    await user.click(screen.getByRole("button", { name: "Add" }));
    await vi.waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual(["shop.example$app=chrome.exe"]));
    expect(rowOf("shop.example")).toHaveTextContent("Google Chrome");
  });

  it.each([
    ["not a host", /cannot hold a space/],
    ["192.0.2.7", /IP address/],
    ["localhost", /needs a dot/],
  ])("an invalid host says why and writes nothing: %s", async (typed, why) => {
    const { runtime, user } = await withRows();
    await user.type(screen.getByRole("textbox", { name: "Add a site not to decrypt" }), typed);
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(within(group()).getByRole("alert")).toHaveTextContent(why);
    expect(runtime.settings.get("filtering.exclusions")).toEqual([]);
  });

  it("a line already there says so and keeps what was typed", async () => {
    const { runtime, user } = await withRows({ lines: ["mine.example"] });
    await user.type(screen.getByRole("textbox", { name: "Add a site not to decrypt" }), "mine.example");
    await user.click(screen.getByRole("button", { name: "Add" }));
    expect(within(group()).getByRole("alert")).toHaveTextContent("already in the list");
    expect(runtime.settings.get("filtering.exclusions")).toEqual(["mine.example"]);
  });

  it("a write the budget refuses is said, as the Filters page says it", async () => {
    const { runtime, user } = await withRows({ lines: ["mine.example"] });
    runtime.settings.set = (() => Promise.reject(new Error("over the budget"))) as never;
    await user.type(screen.getByRole("textbox", { name: "Add a site not to decrypt" }), "more.example");
    await user.click(screen.getByRole("button", { name: "Add" }));
    await vi.waitFor(() => expect(runtime.notices.list().some((n) => n.kind === "error" && n.text === "over the budget")).toBe(true));
  });

  it("remove with undo", async () => {
    const { runtime, user } = await withRows({ lines: ["mine.example$app=client.exe"] });
    await user.click(screen.getByRole("button", { name: "Remove mine.example$app=client.exe" }));
    await vi.waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual([]));
    expect(screen.queryByText("mine.example")).toBeNull();
    const undo = runtime.notices.list().find((n) => n.action?.label === "Undo");
    act(() => undo?.action?.run());
    await vi.waitFor(() => expect(runtime.settings.get("filtering.exclusions")).toEqual(["mine.example$app=client.exe"]));
  });

  it("try decrypting again takes the row away, with its app", async () => {
    const engine = createMockEngine("idle", { heal: true });
    const tryAgain = vi.spyOn(engine, "tryDecryptAgain");
    const { user } = await withRows({ engine });
    await user.click(within(rowOf('"pin.example"')).getByRole("button", { name: 'Try decrypting "pin.example" again' }));
    expect(tryAgain).toHaveBeenCalledExactlyOnceWith('"pin.example"', "client.exe");
    await vi.waitFor(() => expect(screen.queryByText('"pin.example"')).toBeNull());
    await user.click(within(rowOf('"ev.example"')).getByRole("button", { name: 'Try decrypting "ev.example" again' }));
    expect(tryAgain).toHaveBeenLastCalledWith('"ev.example"', null);
  });

  it("try all, for the app the view is filtered to", async () => {
    const engine = createMockEngine("idle", { heal: true });
    const tryAgain = vi.spyOn(engine, "tryDecryptAgain");
    const { user } = await withRows({ engine, search: "?exclusionsApp=client.exe&exclusionsReason=pinning" });
    expect(lines()).toEqual(['"pin.example"']);
    await user.click(screen.getByRole("button", { name: "Try decrypting all again" }));
    expect(tryAgain).toHaveBeenCalledExactlyOnceWith(null, "client.exe");
    await vi.waitFor(() => expect(screen.queryByText('"pin.example"')).toBeNull());
    expect(screen.queryByRole("button", { name: "Try decrypting all again" }), "nothing left to try").toBeNull();
  });

  it("no try all with no app, or for an app with nothing rejected", async () => {
    await withRows();
    expect(screen.queryByRole("button", { name: "Try decrypting all again" })).toBeNull();
    cleanup();
    await setup({ search: "?exclusionsApp=other.exe" });
    await screen.findByText("bank.example");
    expect(screen.queryByRole("button", { name: "Try decrypting all again" })).toBeNull();
    await userEvent.setup().click(screen.getByRole("button", { name: "Show every app" }));
    expect(window.location.search).toBe("");
  });

  it("a refused try is said, and the row stays", async () => {
    const engine = createMockEngine("idle", { heal: true });
    engine.tryDecryptAgain = async () => Promise.reject(new Error("not an exclusion line"));
    const { user } = await withRows({ engine });
    await user.click(within(rowOf('"pin.example"')).getByRole("button", { name: 'Try decrypting "pin.example" again' }));
    expect(await within(group()).findByRole("alert")).toHaveTextContent("not an exclusion line");
    expect(lines()).toContain('"pin.example"');
  });

  it("names the floor once", async () => {
    await withRows();
    expect(group().querySelectorAll("[data-exclusions-floor]")).toHaveLength(1);
    expect(group()).toHaveTextContent(FLOOR_LINE);
    expect(lines().join(" ")).not.toContain("floor:");
  });

  it("not in force: the user's rows only, and one line that says so", async () => {
    await setup({ engine: createMockEngine("idle"), lines: ["mine.example"] });
    await screen.findByText("mine.example");
    expect(group()).toHaveTextContent(NOT_IN_FORCE_LINE);
    expect(lines()).toEqual(["mine.example"]);
    expect(group().querySelectorAll("[data-exclusions-floor]")).toHaveLength(1);
    expect(screen.queryByRole("radiogroup"), "one group is no choice").toBeNull();
  });

  it("not in force with no line: says so, and the form still works", async () => {
    await setup({ engine: createMockEngine("missing") });
    expect(group()).toHaveTextContent("No site is on this list yet.");
    expect(screen.getByRole("textbox", { name: "Add a site not to decrypt" })).toBeEnabled();
  });

  it("shows the first rows and counts the rest", async () => {
    const { runtime } = await withRows();
    const many: ExclusionRow[] = Array.from({ length: EXCLUSIONS_SHOWN + 7 }, (_, i) => ({ line: `h${i}.example`, apps: [], reason: "list:x", created_ms: null, retries: 0 }));
    await withSlice(runtime, { exclusions: { revision: 4, rows: many, scope: "browsers", browsers: [], skipped: 0 } });
    expect(lines()).toHaveLength(EXCLUSIONS_SHOWN);
    expect(group().querySelector("[data-exclusions-more]")).toHaveTextContent("7 more, search to narrow");
  });
});

describe("Not decrypted, degraded data (the done-gate)", () => {
  const healthy = async () => (await withRows()).runtime;

  it("an engine error: says so and keeps the rows", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusionsError: "the pipe closed" });
    expect(within(group()).getByRole("alert")).toHaveTextContent("Sieve could not read this list: the pipe closed");
    expect(lines()).toHaveLength(4);
  });

  it("null rows", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: { revision: 4, rows: null as unknown as ExclusionRow[], scope: "browsers", browsers: [], skipped: 0 } });
    expect(group()).toHaveTextContent("No site is on this list yet.");
  });

  it("no facts at all", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: null });
    expect(group()).toHaveTextContent("No site is on this list yet.");
  });

  it("rows with missing fields", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: { revision: 4, rows: [{ line: "partial.example" } as ExclusionRow, { reason: "auto:pinning" } as ExclusionRow, {} as ExclusionRow], scope: "browsers", browsers: [], skipped: 0 } });
    expect(rowOf("partial.example")).toHaveTextContent("All apps");
  });

  it("a row of the wrong type", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: { revision: 4, rows: [null, 7, "x"] as unknown as ExclusionRow[], scope: "browsers", browsers: [], skipped: 0 } });
    expect(group()).toBeInTheDocument();
  });

  it("an unknown reason shows as it came", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: { revision: 4, rows: [{ line: "x.example", apps: [], reason: "auto:someday", created_ms: null, retries: 0 }], scope: "browsers", browsers: [], skipped: 0 } });
    expect(rowOf("x.example")).toHaveTextContent("auto:someday");
  });

  it("rows that could not be read are counted", async () => {
    const rt = await healthy();
    await withSlice(rt, { exclusions: { revision: 4, rows: [], scope: "browsers", browsers: [], skipped: 2 } });
    expect(group().querySelector("[data-exclusions-skipped]")).toHaveTextContent("2 rows could not be read");
  });

  it("an old engine answering an error to the new types", async () => {
    const engine = createMockEngine("idle", { heal: true });
    engine.healNotices = async () => Promise.reject(new Error("unknown variant `heal_notices`"));
    await setup({ engine, lines: ["mine.example"] });
    expect(await within(group()).findByRole("alert")).toHaveTextContent("unknown variant");
    expect(lines()).toEqual(["mine.example"]);
  });

  it("the switch stays unavailable: this view holds no way to turn it on", async () => {
    const { runtime } = await setup({ engine: createMockEngine("idle") });
    expect(runtime.settings.get(HTTPS_SWITCH as "filtering.https")).toBe(false);
    expect(screen.queryByRole("switch")).toBeNull();
  });
});
