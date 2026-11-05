/**
 * Mock engine: answers `probe` with one of the examples of the wire fixture
 * (src/data/fixtures/engine-probe-v2.json), so the browser, tests and e2e
 * show exactly the shapes Rust produces. Query string `?engine=<scenario>`,
 * default `missing` (a browser has no engine). `error` makes every probe
 * fail, as an unreadable service manager would.
 *
 * The actions move between the fixture's examples the way the engine would:
 * turning routing on from `idle` routes; off from any welcome state is idle;
 * pausing AdGuard lets a waiting engine route (the `filtering` example has
 * AdGuard's service stopped); starting it again makes the engine wait.
 * Nothing else is invented.
 *
 * The certificate answers `certStatuses` of the IPC fixture, chosen by
 * `?cert=<scenario>` (default `not_installed`); `error` makes each read fail.
 * Turning `https` off leaves `policy_off`, and on or Reinstall leaves
 * `installed`, as the engine does; Reinstall is refused while `https` is off.
 */
import ipc from "./fixtures/engine-ipc-v2.json";
import fixture from "./fixtures/engine-probe-v2.json";
import type { EngineSource } from "./engine-source";
import {
  parseCertStatus,
  parseEngineProbe,
  parseEngineStatus,
  type CertStatus,
  type EnginePolicy,
  type EngineProbe,
  type EngineStatus,
} from "./protocol";

export const ENGINE_SCENARIOS = [
  "missing",
  "stopped",
  "starting",
  "idle",
  "filtering",
  "adguard",
  "vpn",
  "crash_loop",
  "setup",
  "incompatible",
  "refused",
  "unreachable",
  "error",
] as const;
export type EngineScenario = (typeof ENGINE_SCENARIOS)[number];

export const CERT_SCENARIOS = ["installed", "expires_soon", "not_installed", "policy_off", "error"] as const;
export type CertScenario = (typeof CERT_SCENARIOS)[number];

export const MOCK_ENGINE_ERROR = "service manager: Access is denied. (os error 5)";
/** What the mock's AdGuard actions answer when they cannot apply (no AdGuard to stop or start). */
export const MOCK_ADGUARD_ERROR = "Adguard Service: the service is not in a state that allows this";
/** The engine's refusals of a certificate request (`?cert=error`, Reinstall with `https` off). */
export const MOCK_CERT_ERROR = "unexpected answer: the engine did not say";
export const MOCK_HTTPS_OFF = "HTTPS filtering is off, so there is no certificate to reinstall";

const WELCOME: readonly EngineScenario[] = ["idle", "filtering", "adguard", "vpn", "crash_loop", "setup"];

function statusOf(scenario: EngineScenario, https: boolean): EngineStatus {
  const example = fixture.examples[scenario as keyof typeof fixture.examples];
  const status = parseEngineStatus((example.pipe as { status: unknown }).status);
  return { ...status, policy: { ...status.policy, https } };
}

function withHttps(probe: EngineProbe, https: boolean): EngineProbe {
  if (probe.pipe?.kind !== "welcome") return probe;
  const status = probe.pipe.status;
  return { ...probe, pipe: { ...probe.pipe, status: { ...status, policy: { ...status.policy, https } } } };
}

export function createMockEngine(start: EngineScenario = "missing", startCert: CertScenario = "not_installed"): EngineSource {
  let scenario = start;
  let cert = startCert;
  let https = false;
  const requireWelcome = () => {
    if (!WELCOME.includes(scenario)) throw new Error("The system cannot find the file specified. (os error 2)");
  };
  const certAnswer = (): CertStatus => {
    if (cert === "error") throw new Error(MOCK_CERT_ERROR);
    return parseCertStatus(ipc.certStatuses[cert]);
  };
  return {
    kind: "mock",
    probe: async () => {
      if (scenario === "error") throw new Error(MOCK_ENGINE_ERROR);
      return withHttps(parseEngineProbe(fixture.examples[scenario]), https);
    },
    setPolicy: async (policy: EnginePolicy) => {
      requireWelcome();
      if (!policy.engine) scenario = "idle";
      else if (scenario === "idle" || scenario === "crash_loop") scenario = "filtering";
      if (https && !policy.https) cert = "policy_off";
      if (!https && policy.https && (cert === "policy_off" || cert === "not_installed")) cert = "installed";
      https = policy.https;
      return statusOf(scenario, https);
    },
    stopAdguard: async () => {
      if (scenario !== "adguard") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "filtering";
    },
    startAdguard: async () => {
      if (scenario !== "filtering") throw new Error(MOCK_ADGUARD_ERROR);
      scenario = "adguard";
    },
    certStatus: async () => {
      requireWelcome();
      return certAnswer();
    },
    installRoot: async () => {
      requireWelcome();
      if (!https) throw new Error(MOCK_HTTPS_OFF);
      cert = "installed";
      return certAnswer();
    },
  };
}
