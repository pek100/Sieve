import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HomeBanner } from "@/components/sieve/home/home-banner";
import { UnlockDialog } from "@/components/sieve/lock/unlock-dialog";
import { ENGINE_SWITCH } from "@/core/engine";
import { LINK_TITLE, UDP_TEXT } from "@/core/link";
import { createMockEngine, MOCK_NOT_A_CODE, type LinkScenario } from "@/data/engine-mock";
import { createMockLock, MOCK_PASSWORD, type LockScenario } from "@/data/lock-mock";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { LinkSection } from "./link-section";

vi.mock("next/navigation", () => ({ usePathname: () => "/settings/" }));
vi.setConfig({ testTimeout: 20_000 });

const CODE = "SL1-EXAMPLEONLYNOTAREALCODE0123456789abcdefghijklmnopqrstuvwxyz";
const NOW = 1_793_000_090_000;
const HUB_FP = "5e1a9c0d4b7f2e8a6c3d1f0b9e7a5c3d2b1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d";

afterEach(() => {
  cleanup();
  localStorage.clear();
});

/** An engine that routes (the switch on), with the link fact as `link` ("none": an engine from before it). */
async function setup(link: LinkScenario, lock: LockScenario = "none") {
  const engine = createMockEngine("filtering", { link, now: () => NOW });
  const pairs: unknown[][] = [];
  const pair = engine.linkPair;
  engine.linkPair = (...args) => {
    pairs.push(args);
    return pair(...args);
  };
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true } }), engine, lock: createMockLock(lock) });
  render(
    <SieveProvider runtime={runtime}>
      <HomeBanner />
      <LinkSection now={() => NOW} />
      <UnlockDialog />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  await waitFor(() => expect(runtime.store.getState().engine.probe?.pipe?.kind).toBe("welcome"));
  return { runtime, engine, pairs, user: userEvent.setup() };
}

const section = () => document.querySelector<HTMLElement>("[data-link-section]");
const homeLine = () => document.querySelector<HTMLElement>("[data-link-home]");

describe("exit through another device, in Settings", () => {
  it("an engine from before it shows nothing of it, here or on Home", async () => {
    await setup("none");
    expect(section()).toBeNull();
    expect(screen.queryByText(LINK_TITLE)).toBeNull();
    expect(homeLine()).toBeNull();
  });

  it("unpaired: the code is masked, gone from the field once sent, sent once, and never shown or kept", async () => {
    const { runtime, pairs, user } = await setup("unpaired");
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "unpaired"));
    expect(screen.getByRole("region", { name: LINK_TITLE })).toHaveTextContent("Not paired with another device.");
    const field = document.querySelector<HTMLInputElement>("[data-link-code]")!;
    expect(field.type).toBe("password");
    await user.click(screen.getByRole("radio", { name: "The other device dials" }));
    expect(section()).toHaveTextContent(/Sieve opens TCP port 7443 .* Sieve does not change Windows Firewall: allow this port yourself, ideally only from the other device's address/);
    await user.type(field, CODE);
    await user.click(screen.getByRole("button", { name: "Pair" }));
    expect(field.value).toBe("");
    expect(pairs).toEqual([[CODE, { how: "listen", port: 7443 }]]);
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "pairing"));
    expect(section()).toHaveTextContent("waiting for the other device to connect to 198.51.100.30:7443");
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "off"), { timeout: 5_000 });
    expect(document.body.innerHTML).not.toContain(CODE);
    expect(JSON.stringify(runtime.settings.doc())).not.toContain(CODE);
    expect(JSON.stringify(runtime.store.getState())).not.toContain(CODE);
    expect(Object.values({ ...localStorage })).not.toContain(CODE);
  });

  it("a code the engine refuses is said in its words, without the code", async () => {
    const { user } = await setup("unpaired");
    await waitFor(() => expect(section()).not.toBeNull());
    const field = document.querySelector<HTMLInputElement>("[data-link-code]")!;
    await user.type(field, "not-a-code-at-all");
    await user.type(screen.getByRole("textbox"), "203.0.113.20:7443");
    await user.click(screen.getByRole("button", { name: "Pair" }));
    const alert = await screen.findByText(`Pairing did not start: ${MOCK_NOT_A_CODE}`);
    expect(alert).toHaveAttribute("role", "alert");
    expect(document.body.innerHTML).not.toContain("not-a-code-at-all");
    expect(field.value).toBe("");
  });

  it("a typed address that is not one is caught before anything is sent", async () => {
    const { pairs, user } = await setup("unpaired");
    await waitFor(() => expect(section()).not.toBeNull());
    await user.type(document.querySelector<HTMLInputElement>("[data-link-code]")!, CODE);
    await user.type(screen.getByRole("textbox"), "somewhere");
    await user.click(screen.getByRole("button", { name: "Pair" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Type an address with its port");
    expect(pairs).toEqual([]);
  });

  it("paired: the device, both fingerprints short with the whole on hover, every choice and what it means", async () => {
    const { engine, user } = await setup("off");
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "off"));
    const s = section()!;
    expect(s).toHaveTextContent("Paired with home");
    expect(s).toHaveTextContent("5e1a9c0d...0a9f8e7d");
    expect(s).not.toHaveTextContent(HUB_FP);
    expect(screen.getByRole("button", { name: `Copy its fingerprint ${HUB_FP}` })).toBeInTheDocument();
    await user.hover(screen.getByRole("button", { name: `Copy its fingerprint ${HUB_FP}` }));
    expect(await screen.findByRole("tooltip")).toHaveTextContent(HUB_FP);
    expect(s).toHaveTextContent(UDP_TEXT.drop);
    for (const words of [/sites see its address, not this computer's/, /apps you turned off in Sieve, and everything while Sieve is paused/, /DNS over QUIC server stays on this computer's own connection/, /never the content of encrypted connections/, /always return this computer to its normal network/]) {
      expect(s).toHaveTextContent(words);
    }
    const setLink = vi.spyOn(engine, "setLink");
    await user.click(screen.getByRole("switch", { name: "Exit through home" }));
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "up"));
    expect(setLink).toHaveBeenLastCalledWith({ exit: true, on_hub_down: "stop", udp: "drop", route: { how: "dial", address: "203.0.113.20:7443" } });
    await waitFor(() => expect(homeLine()).toHaveTextContent("Exiting through home: sites see its address, not this computer's."));
    await user.click(within(screen.getByRole("radiogroup", { name: "Other UDP" })).getByRole("radio", { name: "Send directly" }));
    expect(setLink).toHaveBeenLastCalledWith(expect.objectContaining({ exit: true, udp: "direct" }));
    await waitFor(() => expect(section()).toHaveTextContent(UDP_TEXT.direct));
  });

  it("unpair asks first, then forgets", async () => {
    const { user } = await setup("off");
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "off"));
    await user.click(screen.getByRole("button", { name: "Unpair" }));
    const dialog = await screen.findByRole("dialog", { name: "Unpair home" });
    expect(dialog).toHaveTextContent("This removes home and this computer's key for it.");
    expect(section()).toHaveAttribute("data-link-section", "off");
    await user.click(within(dialog).getByRole("button", { name: "Unpair" }));
    await waitFor(() => expect(section()).toHaveAttribute("data-link-section", "unpaired"));
  });

  it("behind the settings password: every control shut until it is given, reading still open", async () => {
    const { engine, user } = await setup("off", "set");
    await waitFor(() => expect(section()?.querySelector("[data-lock=password]")).not.toBeNull());
    expect(section()).toHaveTextContent("Paired with home");
    expect(screen.getByRole("switch", { name: "Exit through home" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Unpair" })).toBeDisabled();
    const setLink = vi.spyOn(engine, "setLink");
    await user.click(within(section()!).getByRole("button", { name: "Unlock" }));
    await user.type(await screen.findByLabelText("Password"), `${MOCK_PASSWORD}{Enter}`);
    await waitFor(() => expect(screen.getByRole("switch", { name: "Exit through home" })).toBeEnabled());
    expect(setLink).not.toHaveBeenCalled();
  });
});

describe("exit through another device, on Home", () => {
  it("while it cannot be reached and the setting stops: says new connections are stopped", async () => {
    await setup("down");
    await waitFor(() => expect(homeLine()).toHaveAttribute("data-link-home", "warning"));
    expect(homeLine()).toHaveTextContent("Home cannot be reached, so sieved apps' new connections are stopped rather than leaving from this computer's own address.");
    expect(section()).toHaveTextContent("The last error: dial 203.0.113.20:7443: timed out: connect.");
  });

  it("while connecting with the setting direct: says they leave directly from this computer", async () => {
    await setup("connecting");
    await waitFor(() => expect(homeLine()).toHaveTextContent("Connecting to home. Until it answers, sieved apps leave directly from this computer, from its own address."));
  });

  it("paired and off: nothing on Home", async () => {
    await setup("off");
    await waitFor(() => expect(section()).not.toBeNull());
    expect(homeLine()).toBeNull();
  });
});
