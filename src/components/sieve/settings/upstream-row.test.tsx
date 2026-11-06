import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { settingDef } from "@/core/settings/registry";
import { MAX_UPSTREAMS, parseUpstream } from "@/core/upstream";
import type { EngineSlice } from "@/core/engine";
import { createMockLock } from "@/data/lock-mock";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { SettingsScreen } from "./settings-screen";
import { UpstreamRow } from "./upstream-row";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

/** What the row reads of the engine, in the degraded tests; null reads the real slice. */
let engineSays: Partial<EngineSlice> | null = null;
vi.mock("@/hooks/use-sieve", async (original) => {
  const actual = await original<typeof import("@/hooks/use-sieve")>();
  return { ...actual, useEngine: () => (engineSays === null ? actual.useEngine() : ({ probe: null, error: null, ...engineSays } as EngineSlice)) };
});

const KEY = "filtering.upstreams";
const DEFAULTS = settingDef(KEY).default as readonly string[];
const A = "tls://a.example";
const B = "quic://b.example";

async function setup(upstreams?: readonly string[], lock?: ReturnType<typeof createMockLock>) {
  const values = upstreams ? { [KEY]: upstreams } : {};
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values }), lock });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
    await new Promise((settled) => setTimeout(settled, 0));
  });
  return runtime;
}

const row = () => within(document.querySelector<HTMLElement>(`[data-setting="${KEY}"]`)!);
const field = () => row().getByRole("textbox", { name: "Add to Upstream DNS servers" });
const addButton = () => row().getByRole("button", { name: "Add" });
const shown = () => row().getAllByRole("listitem").map((li) => li.getAttribute("data-upstream"));

async function add(text: string, kind?: "DoH" | "DoT" | "DoQ") {
  if (kind) await userEvent.click(row().getByRole("radio", { name: kind }));
  await userEvent.clear(field());
  await userEvent.type(field(), text);
  await userEvent.click(addButton());
}

describe("the upstream editor", () => {
  it.each([
    ["DoH", "dns.example", "https://dns.example/dns-query"],
    ["DoT", "dns.example", "tls://dns.example"],
    ["DoQ", "dns.example", "quic://dns.example"],
  ] as const)("adds with %s selected", async (kind, typed, want) => {
    const rt = await setup();
    await add(typed, kind);
    expect(rt.settings.get(KEY)).toEqual([...DEFAULTS, want]);
    expect(shown()).toEqual([...DEFAULTS, want]);
    expect(field()).toHaveValue("");
  });

  it("a pasted URL keeps its own kind, and the segment follows it", async () => {
    const rt = await setup();
    await userEvent.click(row().getByRole("radio", { name: "DoH" }));
    await userEvent.type(field(), "quic://paste.example:8853");
    expect(row().getByRole("radio", { name: "DoQ" })).toBeChecked();
    await userEvent.click(addButton());
    expect(rt.settings.get(KEY).at(-1)).toBe("quic://paste.example:8853");
  });

  it("every address it can add, the grammar accepts", async () => {
    const rt = await setup();
    await add("2001:db8::1", "DoT");
    await add("192.0.2.1:8853", "DoQ");
    await add("dns.example/custom?x=1", "DoH");
    for (const raw of rt.settings.get(KEY)) expect(parseUpstream(raw), raw).not.toBeNull();
    expect(rt.settings.get(KEY).slice(-3)).toEqual(["tls://[2001:db8::1]", "quic://192.0.2.1:8853", "https://dns.example/custom?x=1"]);
  });

  it.each(["udp://1.1.1.1", "http://dns.example/dns-query", "tls://dns.example/x", "a!b.example"])("refuses %j with its reason and changes nothing", async (typed) => {
    const rt = await setup();
    await add(typed, "DoT");
    expect(row().getByRole("alert")).toHaveTextContent("Not an encrypted address");
    expect(rt.settings.get(KEY)).toEqual(DEFAULTS);
    expect(field()).toHaveValue(typed);
    await userEvent.type(field(), "x");
    expect(row().queryByRole("alert"), "typing clears it").toBeNull();
  });

  it("refuses a repeat after parsing, as the engine would", async () => {
    const rt = await setup([A]);
    await add("tls://A.example:853");
    expect(row().getByRole("alert")).toHaveTextContent("Already listed");
    expect(rt.settings.get(KEY)).toEqual([A]);
  });

  it("disables Add at the limit and says so", async () => {
    const full = Array.from({ length: MAX_UPSTREAMS }, (_, i) => `tls://n${i}.example`);
    const rt = await setup(full);
    await userEvent.type(field(), "more.example");
    expect(addButton()).toBeDisabled();
    expect(row().getByText(`The engine takes at most ${MAX_UPSTREAMS} servers.`)).toBeInTheDocument();
    expect(rt.settings.get(KEY)).toEqual(full);
  });

  it("moves change the setting's order, and the first up and the last down are disabled", async () => {
    const rt = await setup([A, B, "tls://c.example"]);
    expect(row().getByRole("button", { name: `Move ${A} up` })).toBeDisabled();
    expect(row().getByRole("button", { name: "Move tls://c.example down" })).toBeDisabled();
    await userEvent.click(row().getByRole("button", { name: `Move ${B} up` }));
    expect(rt.settings.get(KEY)).toEqual([B, A, "tls://c.example"]);
    await userEvent.click(row().getByRole("button", { name: `Move ${A} down` }));
    expect(rt.settings.get(KEY)).toEqual([B, "tls://c.example", A]);
    expect(shown()).toEqual([B, "tls://c.example", A]);
  });

  it("focus stays in the row when a move to the end disables the button pressed", async () => {
    await setup([A, B]);
    await userEvent.click(row().getByRole("button", { name: `Move ${B} up` }));
    expect(document.activeElement).not.toBe(document.body);
    expect(document.activeElement?.closest("[data-upstream]")?.getAttribute("data-upstream")).toBe(B);
  });

  it("removes an entry, never the only one", async () => {
    const rt = await setup([A, B]);
    await userEvent.click(row().getByRole("button", { name: `Remove ${A}` }));
    expect(rt.settings.get(KEY)).toEqual([B]);
    expect(row().getByRole("button", { name: `Remove ${B}` })).toBeDisabled();
  });

  it("resets to the defaults", async () => {
    const rt = await setup([A]);
    await userEvent.click(row().getByRole("button", { name: "Reset Upstream DNS servers" }));
    expect(rt.settings.get(KEY)).toEqual(DEFAULTS);
    expect(row().queryByRole("button", { name: /^Reset/ })).toBeNull();
  });

  it("Reset with text typed leaves exactly the defaults and keeps the text", async () => {
    const rt = await setup([A]);
    await userEvent.type(field(), "typed.example");
    await userEvent.click(row().getByRole("button", { name: "Reset Upstream DNS servers" }));
    expect(rt.settings.get(KEY)).toEqual(DEFAULTS);
    expect(field()).toHaveValue("typed.example");
  });

  it("Reset with an empty field shows no alert", async () => {
    const rt = await setup([A]);
    await userEvent.click(row().getByRole("button", { name: "Reset Upstream DNS servers" }));
    expect(rt.settings.get(KEY)).toEqual(DEFAULTS);
    expect(row().queryByRole("alert")).toBeNull();
  });

  it("Reset at the limit with text typed leaves exactly the defaults", async () => {
    const rt = await setup(Array.from({ length: MAX_UPSTREAMS }, (_, i) => `tls://n${i}.example`));
    await userEvent.type(field(), "more.example");
    await userEvent.click(row().getByRole("button", { name: "Reset Upstream DNS servers" }));
    expect(rt.settings.get(KEY)).toEqual(DEFAULTS);
  });

  it("locked by the password, every control is disabled at the value in force", async () => {
    await setup([A, B], createMockLock("set"));
    const editor = within(document.querySelector<HTMLElement>("[data-upstream-editor]")!);
    expect(editor.getAllByRole("button").length).toBeGreaterThan(4);
    for (const button of editor.getAllByRole("button")) expect(button, button.getAttribute("aria-label") ?? "").toBeDisabled();
    for (const radio of editor.getAllByRole("radio")) expect(radio).toBeDisabled();
    expect(field()).toBeDisabled();
    expect(shown()).toEqual([A, B]);
    expect(row().getByRole("button", { name: /unlock/i }), "the way out stays open, beside the reason").toBeEnabled();
  });
});

describe("the upstream editor, degraded data", () => {
  const props = { label: "Upstream DNS servers", disabled: false, onChange: () => {}, reset: null };

  afterEach(() => {
    engineSays = null;
  });

  function withEngine(ui: React.ReactNode, engine: Partial<EngineSlice>) {
    engineSays = engine;
    return render(ui);
  }

  it.each([[null], [undefined], [[]]])("held %j shows no read-back line", (heldUpstreams) => {
    withEngine(<UpstreamRow {...props} value={[A]} />, { heldUpstreams });
    expect(document.querySelector("[data-upstream-readback]")).toBeNull();
  });

  it("reads back what the engine holds, and a list it does not hold says so", () => {
    const { unmount } = withEngine(<UpstreamRow {...props} value={[A, B]} />, { heldUpstreams: [A, B] });
    expect(document.querySelector("[data-upstream-readback]")).toHaveTextContent("The engine uses this list.");
    unmount();
    withEngine(<UpstreamRow {...props} value={[A, B]} />, { heldUpstreams: [B, A] });
    expect(document.querySelector("[data-upstream-readback]")).toHaveTextContent(`The engine still uses: ${B}, ${A}.`);
  });

  it("an unparsable entry from an old store renders as text with Remove", async () => {
    const onChange = vi.fn();
    withEngine(<UpstreamRow {...props} onChange={onChange} value={["1.1.1.1", A]} />, {});
    expect(screen.getByText("1.1.1.1")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove 1.1.1.1" }));
    expect(onChange).toHaveBeenCalledWith([A]);
  });

  it("a value of the wrong shape renders an empty list and the form", () => {
    for (const value of [null, undefined, "tls://a.example", 7, { a: 1 }, [1, null, A]]) {
      const { unmount } = withEngine(<UpstreamRow {...props} value={value} />, {});
      expect(screen.getByRole("textbox", { name: "Add to Upstream DNS servers" })).toBeInTheDocument();
      unmount();
    }
  });

  it("a mock engine answering a malformed list leaves the row standing", () => {
    for (const heldUpstreams of ["tls://a.example", 7, { upstreams: [] }]) {
      const { unmount } = withEngine(<UpstreamRow {...props} value={[A]} />, { heldUpstreams: heldUpstreams as never });
      expect(document.querySelector("[data-upstream-readback]")).toBeNull();
      expect(screen.getByText(A)).toBeInTheDocument();
      unmount();
    }
  });

  it("the engine's refusal shows on this row", () => {
    withEngine(<UpstreamRow {...props} value={[A]} />, { dnsError: "The DNS servers did not reach the engine: refused" });
    expect(screen.getByRole("alert")).toHaveTextContent("did not reach the engine");
  });
});
