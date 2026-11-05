import { act, cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HTTPS_SWITCH, ENGINE_SWITCH, CERT_STATE_UNKNOWN, type EngineSlice } from "@/core/engine";
import ipc from "@/data/fixtures/engine-ipc-v2.json";
import { createMockEngine, MOCK_CERT_ERROR, type CertScenario, type EngineScenario } from "@/data/engine-mock";
import { createTauriEngine, type EngineSource } from "@/data/engine-source";
import { createMockSource } from "@/data/mock-source";
import type { CertStatus } from "@/data/protocol";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { CertificateGroup } from "./certificate-group";

// `filtering.https` is unavailable until slice 6, which reads it as off and so
// sends the engine off. These tests are about the group, with the switch real:
// law 11 holds the real registry (the same split as dns-card.test.tsx).
vi.mock("@/core/settings/registry", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/core/settings/registry")>()),
  isAvailable: () => true,
}));
vi.setConfig({ testTimeout: 20_000 });

afterEach(cleanup);

const THUMBPRINT = ipc.certStatuses.installed.thumbprint;

async function setup(engine: EngineSource, https = false) {
  const settings = memoryBackend(https ? { schema: 4, values: { [ENGINE_SWITCH]: false, [HTTPS_SWITCH]: true } } : undefined);
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings, engine });
  render(
    <SieveProvider runtime={runtime}>
      <CertificateGroup />
    </SieveProvider>,
  );
  await act(async () => {
    await runtime.settings.ready;
  });
  return runtime;
}

const mock = (engine: EngineScenario = "idle", cert: CertScenario = "not_installed") => createMockEngine(engine, cert);
const group = () => screen.getByRole("region", { name: "Certificate" });
const state = () => group().querySelector("[data-certificate-state]")!.textContent;
const settled = (text: string) => vi.waitFor(() => expect(state()).toBe(text));
const rowLabels = () => within(group()).queryAllByRole("term").map((t) => t.textContent);

/** The group reached with a shape no normalizer ever passed: the render path holds regardless. */
async function withSlice(patch: Partial<EngineSlice>) {
  const runtime = await setup(mock("idle"));
  await settled("Not installed");
  act(() => runtime.store.setEngine({ ...runtime.store.getState().engine, ...patch }));
  return runtime;
}

describe("Certificate group", () => {
  it.each([
    ["installed", "Installed", "Uses Windows certificates"],
    ["expires_soon", "Expires soon", "Does not use Windows certificates"],
  ] as const)("%s: the state and every fact the engine has", async (scenario, words, firefox) => {
    await setup(mock("idle", scenario));
    await settled(words);
    const rows = group();
    expect(rows).toHaveTextContent("Valid until");
    expect(rows).toHaveTextContent(THUMBPRINT);
    expect(rows).toHaveTextContent(firefox);
  });

  it("not installed: only the state line, no rows and no Remove", async () => {
    await setup(mock("idle", "not_installed"));
    await settled("Not installed");
    expect(rowLabels()).toEqual([]);
    expect(within(group()).queryByRole("button")).toBeNull();
  });

  it("a Firefox that is not installed says so", async () => {
    const answer: CertStatus = { ...(ipc.certStatuses.installed as CertStatus), firefox: "not_installed" };
    await setup({ ...mock(), certStatus: async () => answer });
    await settled("Installed");
    expect(group()).toHaveTextContent("FirefoxNot installed");
  });

  it("a row with no fact is left out, never a dash", async () => {
    const answer: CertStatus = { state: "installed", valid_until_ms: null, thumbprint: null, firefox: "uses_windows", last_rotation_ms: null, last_error: null };
    await setup({ ...mock(), certStatus: async () => answer });
    await settled("Installed");
    expect(rowLabels()).toEqual(["Firefox"]);
    expect(group()).not.toHaveTextContent(/-{1,2}$/);
    const rotated: CertStatus = { ...(ipc.certStatuses.installed as CertStatus) };
    cleanup();
    await setup({ ...mock(), certStatus: async () => rotated });
    await settled("Installed");
    expect(rowLabels()).toEqual(["Valid until", "Thumbprint", "Firefox", "Last rotation"]);
  });

  it("the engine's last error is an alert; so is a failed read", async () => {
    await setup(mock("idle", "expires_soon"));
    await settled("Expires soon");
    expect(within(group()).getByRole("alert")).toHaveTextContent(ipc.certStatuses.expires_soon.last_error!);
    cleanup();
    await setup(mock("idle", "error"));
    await settled(CERT_STATE_UNKNOWN);
    expect(within(group()).getByRole("alert")).toHaveTextContent(MOCK_CERT_ERROR);
  });

  it("with no answer from the engine the state is unknown and one line says why", async () => {
    await setup(mock("missing"));
    await settled(CERT_STATE_UNKNOWN);
    expect(group()).toHaveTextContent("The engine is not installed");
    expect(rowLabels()).toEqual([]);
    expect(within(group()).queryByRole("button")).toBeNull();
  });

  it("the thumbprint copies, and the result goes through the notices", async () => {
    const writeText = vi.fn(async () => {});
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const rt = await setup(mock("idle", "installed"));
    await settled("Installed");
    await user.click(within(group()).getByRole("button", { name: `Copy thumbprint ${THUMBPRINT}` }));
    expect(writeText).toHaveBeenCalledWith(THUMBPRINT);
    await vi.waitFor(() => expect(rt.notices.list().map((n) => [n.kind, n.text])).toEqual([["success", "Thumbprint copied"]]));
  });

  it("a copy that fails says so", async () => {
    const user = userEvent.setup();
    Object.defineProperty(navigator, "clipboard", { value: { writeText: vi.fn(async () => Promise.reject(new Error("denied"))) }, configurable: true });
    const rt = await setup(mock("idle", "installed"));
    await settled("Installed");
    await user.click(within(group()).getByRole("button", { name: /Copy thumbprint/ }));
    await vi.waitFor(() => expect(rt.notices.list().map((n) => n.kind)).toEqual(["error"]));
  });

  it("Remove asks first: cancel keeps it, confirm turns the switch off and the root goes", async () => {
    const user = userEvent.setup();
    const rt = await setup(mock("idle", "installed"), true);
    await settled("Installed");
    await vi.waitFor(() => expect(within(group()).getByRole("button", { name: "Reinstall certificate" })).toBeEnabled());

    await user.click(within(group()).getByRole("button", { name: "Remove certificate" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("turns HTTPS filtering off");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(rt.settings.get(HTTPS_SWITCH)).toBe(true);

    await user.click(within(group()).getByRole("button", { name: "Remove certificate" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Remove certificate" }));
    expect(rt.settings.get(HTTPS_SWITCH)).toBe(false);
    await vi.waitFor(() => expect(within(group()).queryByRole("button", { name: "Reinstall certificate" })).toBeNull());
  });

  it("Reinstall shows only while the engine holds HTTPS on, is disabled while busy, and calls the engine", async () => {
    let finish: (answer: CertStatus) => void = () => {};
    const installRoot = vi.fn(() => new Promise<CertStatus>((resolve) => (finish = resolve)));
    const user = userEvent.setup();
    await setup({ ...mock("idle", "installed"), installRoot }, true);
    const button = () => within(group()).getByRole("button", { name: /Reinstall|Reinstalling/ });
    await vi.waitFor(() => expect(button()).toBeEnabled());
    await user.click(button());
    expect(installRoot).toHaveBeenCalledOnce();
    expect(button()).toBeDisabled();
    expect(button()).toHaveTextContent("Reinstalling certificate");
    await act(async () => finish(ipc.certStatuses.installed as CertStatus));
    await vi.waitFor(() => expect(button()).toBeEnabled());
    cleanup();
    await setup(mock("idle", "installed"));
    await settled("Installed");
    expect(within(group()).queryByRole("button", { name: /Reinstall/ })).toBeNull();
  });

  it("a failed Reinstall is an alert", async () => {
    const user = userEvent.setup();
    await setup({ ...mock("idle", "installed"), installRoot: async () => Promise.reject(new Error("the store is locked")) }, true);
    await vi.waitFor(() => expect(within(group()).getByRole("button", { name: "Reinstall certificate" })).toBeEnabled());
    await user.click(within(group()).getByRole("button", { name: "Reinstall certificate" }));
    await vi.waitFor(() => expect(group().querySelector("[data-certificate-action-error]")).toHaveTextContent("not reinstalled: the store is locked"));
  });
});

describe("Certificate group on degraded data", () => {
  const through = (answer: unknown) =>
    createTauriEngine((async (cmd: string) => (cmd === "engine_probe" ? (await createMockEngine("idle").probe()) : answer)) as never);

  it.each([
    ["null", null, /cert status/],
    ["partial", { state: "installed" }, /cert\.valid_until_ms/],
    ["old schema", { installed: true, thumbprint: "ab" }, /cert\.state/],
    ["unknown state", { ...ipc.certStatuses.installed, state: "revoked" }, /cert\.state/],
    ["unknown firefox", { ...ipc.certStatuses.installed, firefox: "maybe" }, /cert\.firefox/],
  ])("a %s answer is refused at the boundary and shown as unknown", async (_name, answer, why) => {
    await setup(through(answer));
    await settled(CERT_STATE_UNKNOWN);
    expect(within(group()).getByRole("alert")).toHaveTextContent(why);
    expect(rowLabels()).toEqual([]);
  });

  it("an engine that answers error to cert_status degrades the same way", async () => {
    await setup({ ...mock(), certStatus: async () => Promise.reject(new Error("unexpected answer")) });
    await settled(CERT_STATE_UNKNOWN);
    expect(within(group()).getByRole("alert")).toHaveTextContent("unexpected answer");
  });

  it.each([
    ["null", null, "Checking"],
    ["undefined", undefined, "Checking"],
    ["an unknown state", { state: "revoked" }, CERT_STATE_UNKNOWN],
    ["no fields", {}, CERT_STATE_UNKNOWN],
    ["bad facts", { state: "installed", valid_until_ms: "soon", thumbprint: null, firefox: "maybe", last_rotation_ms: Number.NaN, last_error: null }, "Installed"],
    ["a date out of range", { state: "installed", valid_until_ms: 1e30, thumbprint: null, firefox: null, last_rotation_ms: null, last_error: null }, "Installed"],
  ])("a store holding %s renders and throws nothing", async (_name, cert, words) => {
    await withSlice({ cert: cert as never, certError: null });
    expect(state()).toBe(words);
    expect(group()).not.toHaveTextContent("This could not load");
    expect(rowLabels()).toEqual([]);
  });
});
