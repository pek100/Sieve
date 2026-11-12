import { act, fireEvent, render, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DNS_CLIENT_CAPTURE, DNS_ENCRYPTION, ENGINE_SWITCH } from "@/core/engine";
import { createMockEngine, MOCK_SIGN_IN_NETWORK } from "@/data/engine-mock";
import fixture from "@/data/fixtures/engine-probe-v3.json";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import { createMockSource } from "@/data/mock-source";
import { parseEngineProbe, type DnsCapture } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime, type Runtime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { captureStateLine, signInPauseLine } from "./dns-capture-state";
import { SettingsScreen } from "./settings-screen";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

async function setup(values: Record<string, unknown> = {}) {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values }) });
  render(
    <SieveProvider runtime={runtime}>
      <SettingsScreen />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return runtime;
}

/** The engine's status as the probe fixture's idle example, with routes up and this capture state (none: an older engine). */
function report(runtime: Runtime, capture: DnsCapture | undefined) {
  const welcome = parseEngineProbe(fixture.examples.idle);
  const pipe = welcome.pipe;
  if (pipe?.kind !== "welcome") throw new Error("the example answers");
  const status = { ...pipe.status, routes_up: true, ...(capture ? { dns_capture: capture } : {}) };
  act(() => runtime.store.setEngine({ ...runtime.store.getState().engine, probe: { ...welcome, pipe: { ...pipe, status } } }));
}

const row = () => document.querySelector<HTMLElement>(`[data-setting="${DNS_CLIENT_CAPTURE}"]`)!;
const stateLine = () => row().querySelector("[data-capture-state]");

describe("Also encrypt Windows' own lookups", () => {
  it("sits right under DNS encryption, on by default, and says what it does and what it costs", async () => {
    await setup();
    const keys = [...document.querySelectorAll("#section-filtering [data-setting]")].map((el) => el.getAttribute("data-setting"));
    expect(keys.indexOf(DNS_CLIENT_CAPTURE)).toBe(keys.indexOf(DNS_ENCRYPTION) + 1);
    const sw = within(row()).getByRole("switch", { name: "Also encrypt Windows' own lookups" });
    expect(sw).toBeChecked();
    expect(sw).toBeEnabled();
    expect(sw).toHaveAccessibleDescription(/Windows' built-in lookups also go through Sieve's encrypted DNS, so the network can't read them/);
    expect(row()).toHaveTextContent(/Can break: Names of nearby PCs found without DNS, and short names that don't exist, answer about 7 s slower/);
    expect(row()).toHaveTextContent(/Sieve offers a one-click pause so its page can open: for up to 15 minutes, or until encrypted DNS answers or the network changes, nearly every app's lookups then go in plain text/);
    expect(row().querySelectorAll("[data-slot=card], [data-slot=badge]"), "flat: no card or chip of its own").toHaveLength(0);
  });

  it("the switch writes the setting, and back", async () => {
    const rt = await setup();
    await userEvent.click(within(row()).getByRole("switch"));
    expect(rt.settings.get(DNS_CLIENT_CAPTURE as never)).toBe(false);
    await userEvent.click(within(row()).getByRole("switch"));
    expect(rt.settings.get(DNS_CLIENT_CAPTURE as never)).toBe(true);
  });

  it("is locked with the reason while DNS encryption is off: with plain DNS there is nothing to encrypt", async () => {
    await setup({ [DNS_ENCRYPTION]: false });
    const sw = within(row()).getByRole("switch");
    expect(sw).toBeDisabled();
    expect(row().querySelector("[data-lock=requires]")).toHaveTextContent("Needs Encrypt DNS lookups, which is off.");
  });

  it("shows the engine's live state: working, or not and why", async () => {
    const rt = await setup();
    expect(stateLine(), "nothing before the engine says").toBeNull();
    report(rt, { state: "working" });
    expect(stateLine()).toHaveAttribute("data-capture-state", "working");
    expect(stateLine()).toHaveTextContent("Working: Windows' own lookups go through Sieve now.");
    report(rt, { state: "not_caught", reason: "tie", adapter: "Ethernet", detail: '"Ethernet" has interface metric 1' });
    expect(stateLine()).toHaveAttribute("data-capture-state", "not_caught");
    expect(stateLine()).toHaveTextContent('the network adapter "Ethernet" has priority 1');
    report(rt, { state: "not_caught", reason: "no_answer", detail: "a probe did not arrive" });
    expect(stateLine()).toHaveTextContent("A firewall rule or another program is in the way.");
  });

  it("says nothing for an older engine, or while the switch is off", async () => {
    const rt = await setup();
    report(rt, undefined);
    expect(stateLine()).toBeNull();
    report(rt, { state: "working" });
    await userEvent.click(within(row()).getByRole("switch"));
    expect(stateLine(), "the switch says it").toBeNull();
    report(rt, { state: "off" });
    expect(stateLine()).toBeNull();
  });

  it("has words for every state the engine can report", () => {
    for (const state of ipc.dnsCaptureStates as DnsCapture[]) {
      const line = captureStateLine(state);
      if (state.state === "off") expect(line).toBeNull();
      else expect(line?.text.length, JSON.stringify(state)).toBeGreaterThan(20);
    }
    expect(captureStateLine({ state: "not_caught", reason: "ipv6_off", detail: "x" })?.text).toMatch(/IPv6 is off on Sieve's network adapter/);
    expect(captureStateLine({ state: "not_caught", reason: "no_ipv4", detail: "x" })?.text).toMatch(/no IPv4 route/);
    expect(captureStateLine({ state: "not_caught", reason: "failed", detail: "FwpmEngineOpen0: error 0x5" })?.text).toContain("FwpmEngineOpen0: error 0x5");
    expect(captureStateLine(undefined)).toBeNull();
  });

  it("a network with nothing to catch, or no IPv4, is a fact, not a warning", async () => {
    const rt = await setup();
    report(rt, { state: "not_caught", reason: "nothing_to_catch", detail: "no network adapter whose DNS queries would leave outside Sieve" });
    expect(stateLine()).toHaveAttribute("data-capture-tone", "neutral");
    expect(stateLine()).toHaveTextContent("Nothing to do on this network");
    expect(stateLine()?.querySelector(".text-warning"), "no warning colour").toBeNull();
    report(rt, { state: "not_caught", reason: "no_ipv4", detail: "x" });
    expect(stateLine()).toHaveAttribute("data-capture-tone", "neutral");
    report(rt, { state: "not_caught", reason: "no_answer", detail: "x" });
    expect(stateLine()).toHaveAttribute("data-capture-tone", "warning");
  });

  it("the sign-in pause says what it changes, for the kind of network, and its time left", () => {
    expect(signInPauseLine(undefined)).toBeNull();
    expect(signInPauseLine({ network: MOCK_SIGN_IN_NETWORK, wifi: true }), "shown, not paused: the notice on Home offers it").toBeNull();
    const line = signInPauseLine({ network: MOCK_SIGN_IN_NETWORK, paused_left_s: 860, wifi: true })!;
    expect(line).toMatch(/^Paused for sign-in\. Nearly every app's lookups go to this Wi-Fi's DNS server in plain text; only apps with their own encrypted DNS are not affected\./);
    expect(line).toContain("Resumes by itself in about 15 min at the latest, or sooner once encrypted DNS answers or the network changes.");
    expect(line, "never that only Windows' own lookups go plain").not.toMatch(/only Windows' own|stay encrypted/);
    expect(signInPauseLine({ network: MOCK_SIGN_IN_NETWORK, paused_left_s: 42 }), "Ethernet, or an engine that does not say: the neutral word").toContain("go to this network's DNS server");
    expect(signInPauseLine({ network: MOCK_SIGN_IN_NETWORK, paused_left_s: 42 })).toContain("in 42 s at the latest");
  });

  it("shows the live pause in the row with Resume now, which ends it with no other step", async () => {
    const engine = createMockEngine("filtering", { signIn: true });
    await engine.pauseDnsCapture(MOCK_SIGN_IN_NETWORK);
    const resume = vi.spyOn(engine, "resumeDnsCapture");
    const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true } }), engine });
    render(
      <SieveProvider runtime={runtime}>
        <SettingsScreen />
      </SieveProvider>,
    );
    await act(async () => {
      await runtime.settings.ready;
    });
    await waitFor(() => expect(stateLine()).toHaveAttribute("data-capture-state", "paused"));
    expect(stateLine()).toHaveTextContent(/Paused for sign-in\. Nearly every app's lookups go to this Wi-Fi's DNS server in plain text/);
    expect(stateLine()).toHaveTextContent(/Resumes by itself in about 15 min/);
    expect(row().querySelectorAll("[data-slot=card], [data-slot=badge]"), "flat").toHaveLength(0);
    await userEvent.click(within(row()).getByRole("button", { name: "Resume now" }));
    expect(resume).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(stateLine()).toHaveAttribute("data-capture-state", "working"));
  });

  it("a Windows error code is said in words, the number in the tooltip", async () => {
    const line = captureStateLine({ state: "not_caught", reason: "failed", detail: "the DNS Client answered a probe with error 9003", code: 9003 });
    expect(line?.text).toMatch(/another DNS server answered Sieve's test lookup before Sieve did/);
    expect(line?.text).not.toMatch(/9003/);
    expect(captureStateLine({ state: "not_caught", reason: "failed", detail: "the DNS Client answered a probe with error 4242", code: 4242 })?.text, "a code with no words keeps the engine's").toContain("error 4242");
    const rt = await setup();
    report(rt, { state: "not_caught", reason: "failed", detail: "the DNS Client answered a probe with error 9003", code: 9003 });
    expect(stateLine()).not.toHaveTextContent("9003");
    fireEvent.pointerMove(stateLine()!, { clientX: 10, clientY: 10 });
    expect(document.querySelector("[role=tooltip][data-capture-code]")).toHaveTextContent("Windows DNS error 9003");
    fireEvent.pointerLeave(stateLine()!);
    expect(document.querySelector("[role=tooltip][data-capture-code]")).toBeNull();
  });
});
