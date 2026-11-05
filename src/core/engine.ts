/**
 * The filtering engine, the pure part: the store slice and what the UI says
 * about it, derived from facts only (plan 1.6.5: "Filtering is not running"
 * comes from facts, never assumed). The facts are `engine_probe`: the
 * Windows service's state and, while it runs, the engine's own answer on
 * its pipe (sieve-ipc v3 Status: policy, blocker, split tunnels, counters).
 *
 * The phase says what routes, and whether anything is blocked is its own fact
 * (`status.blocking`): routing with no list compiled yet closes nothing, and
 * the copy must not claim it does.
 *
 * The slice has one writer, the engine controller (src/data/engine-controller.ts).
 */
import type { EngineBlocker, EngineProbe, EngineStatus } from "@/data/protocol";

/** How often the engine is asked while Sieve is open (plan 1.6.5). */
export const ENGINE_POLL_MS = 2000;

/** The data switch that routes traffic through the engine (registry key; UI reads it from here). */
export const ENGINE_SWITCH = "filtering.engine";

/** The Engine block's anchor in Settings (Settings > Engine), and the link to it (Home's Engine tile). */
export const ENGINE_ANCHOR = "engine";
export const ENGINE_HREF = `/settings/#${ENGINE_ANCHOR}`;

/** AdGuard for Windows' service, the one Sieve offers to stop and start (src-tauri/src/adguard.rs, the engine's coexist::ADGUARD_SERVICE). */
export const ADGUARD_SERVICE = "Adguard Service";

/** What the app is doing to AdGuard right now, for the pause offer's buttons. */
export type AdguardAction = "stopping" | "starting" | null;

export interface EngineSlice {
  /** Newest probe; null before the first answer or after a failed read. */
  probe: EngineProbe | null;
  /** Why the newest read failed; null after a good one. */
  error: string | null;
  /** An AdGuard stop or start the user asked for, while Windows runs it. */
  adguard?: AdguardAction;
  /** Why the last AdGuard stop or start, or policy change, failed; null after a good one. */
  actionError?: string | null;
}

export const EMPTY_ENGINE: EngineSlice = { probe: null, error: null, adguard: null, actionError: null };

export const ENGINE_PHASES = [
  "checking",
  "unreadable",
  "not_installed",
  "not_running",
  "refused",
  "incompatible",
  "idle",
  "starting",
  "routing",
  "adguard",
  "vpn",
  "crash_loop",
  "setup_failed",
] as const;
export type EnginePhase = (typeof ENGINE_PHASES)[number];

/** The engine's own Status, when it answered. */
export function engineStatus(e: EngineSlice): EngineStatus | null {
  const pipe = e.probe?.pipe;
  return pipe?.kind === "welcome" ? pipe.status : null;
}

const BLOCKER_PHASE: Record<EngineBlocker["kind"], EnginePhase> = {
  adguard: "adguard",
  vpn: "vpn",
  crash_loop: "crash_loop",
  setup: "setup_failed",
};

export function enginePhase(e: EngineSlice): EnginePhase {
  if (e.error !== null) return "unreadable";
  const p = e.probe;
  if (p === null) return "checking";
  if (p.service === "missing") return "not_installed";
  if (p.service !== "running" || p.pipe === null) return "not_running";
  switch (p.pipe.kind) {
    case "unreachable":
      return "not_running";
    case "refused":
      return "refused";
    case "incompatible":
      return "incompatible";
    case "welcome": {
      const s = p.pipe.status;
      if (s.filtering) return "routing";
      if (!s.policy.engine) return "idle";
      return s.blocker ? BLOCKER_PHASE[s.blocker.kind] : "starting";
    }
  }
}

/**
 * A policy needs a successful read, a running service and its accepted
 * handshake with Status. A retained Status alone is not permission to send.
 * Settings and the controller share this predicate.
 */
export function engineTakesPolicy(e: EngineSlice): boolean {
  return e.error === null && e.probe?.service === "running" && engineStatus(e) !== null;
}

/**
 * Why a setting the engine carries out (registry `needsEngine`) cannot be
 * changed now, one line per phase that cannot take a policy.
 */
export const ENGINE_LOCK_TEXT = {
  checking: "Sieve is still asking whether the engine is installed.",
  unreadable: "Sieve could not read the engine's state, so it cannot control the engine.",
  not_installed: "The engine is not installed, so there is nothing to control. The Sieve installer adds it.",
  not_running: "The engine is not running, so it cannot take this change.",
  refused: "This copy of Sieve is not the installed one, so it cannot control the engine. Open Sieve from the Start menu.",
  incompatible: "This app and the engine speak different versions, so it cannot control the engine. Reinstall Sieve so both match.",
} satisfies Partial<Record<EnginePhase, string>>;

export type EngineUnreached = keyof typeof ENGINE_LOCK_TEXT;
/** Derived from the phase explanations; engine.test.ts checks them against handshake facts. */
export const ENGINE_UNREACHED = Object.keys(ENGINE_LOCK_TEXT) as EngineUnreached[];

/** The lock reason for a `needsEngine` setting, or null while the engine can take a policy. */
export function engineLockReason(e: EngineSlice): string | null {
  const phase = enginePhase(e);
  return engineTakesPolicy(e) ? null : ENGINE_LOCK_TEXT[phase as EngineUnreached];
}

/** The engine's own routing switch in force (its Status's policy), or null when it did not say. */
export function engineInForce(e: EngineSlice): boolean | null {
  return engineStatus(e)?.policy.engine ?? null;
}

/** The state in a few words (the Engine block's status line, Home's Engine tile). */
export const ENGINE_STATE_TEXT: Record<EnginePhase, string> = {
  checking: "Checking",
  unreadable: "Unknown",
  not_installed: "Not installed",
  not_running: "Not running",
  refused: "Installed",
  incompatible: "Installed, needs an update",
  idle: "Installed, not routing",
  starting: "Starting",
  routing: "Routing traffic",
  adguard: "Waiting for AdGuard",
  vpn: "Paused for a VPN",
  crash_loop: "Stopped after repeated failures",
  setup_failed: "Could not start",
};

/** The exact words of the pause offer (the user's decision: the UI says exactly what happens). */
export const ADGUARD_PAUSE_TEXT =
  "Pausing AdGuard stops its Windows service (Adguard Service). Windows asks you to approve it. AdGuard stops protecting this computer until you start it again here.";

/** Phases whose detail is a problem the user should read. */
export const ENGINE_PROBLEMS: ReadonlySet<EnginePhase> = new Set<EnginePhase>([
  "unreadable",
  "refused",
  "incompatible",
  "crash_loop",
  "setup_failed",
]);

/** One sentence on what the facts mean; never claims filtering or blocking that is not happening. */
export function engineDetail(e: EngineSlice): string {
  const phase = enginePhase(e);
  const p = e.probe;
  const pipe = p?.pipe ?? null;
  const blocker = engineStatus(e)?.blocker ?? null;
  switch (phase) {
    case "checking":
      return "Asking Windows whether Sieve's filtering engine is installed.";
    case "unreadable":
      return `Sieve could not read the engine's state: ${e.error}`;
    case "not_installed":
      return "Sieve's filtering engine is not installed on this computer. The Sieve installer adds it.";
    case "not_running":
      return pipe?.kind === "unreachable"
        ? `The engine's service runs but does not answer: ${pipe.message}`
        : "The engine is installed, but its Windows service is not running. Your network works as usual.";
    case "refused":
      return `The engine answered: ${pipe?.kind === "refused" ? pipe.message : ""}. This copy of Sieve is not the installed one, so it cannot read the engine's status.`;
    case "incompatible":
      return pipe?.kind === "incompatible"
        ? `This app and the engine speak different versions (the engine supports ${pipe.supported[0]} to ${pipe.supported[1]}). Reinstall Sieve so both match.`
        : "";
    case "idle":
      return "The engine runs and changes nothing: no traffic goes through it.";
    case "starting":
      return "The engine is bringing up its network adapter and routes.";
    case "routing":
      return engineStatus(e)?.blocking
        ? "This computer's traffic goes through the engine, which shows each app's connections and closes connections to blocked hosts."
        : "This computer's traffic goes through the engine, which shows each app's connections. Nothing is blocked yet.";
    case "adguard":
      return "AdGuard is protecting this computer, and two filters would capture each other's connections. Sieve routes nothing while AdGuard's service runs; your network works as usual.";
    case "vpn":
      return `Paused while ${blocker?.kind === "vpn" ? blocker.adapter : "a VPN"} is connected. Sieve steps aside for a VPN that carries all traffic and resumes when it disconnects.`;
    case "crash_loop":
      return `The engine restarted ${blocker?.kind === "crash_loop" ? blocker.starts : "several"} times within an hour, so it stopped routing. Your network works as usual. Turn routing off and on to try again.`;
    case "setup_failed":
      return `The engine could not set up its network adapter, so it routes nothing: ${blocker?.kind === "setup" ? blocker.message : ""}`;
  }
}

/** The text beside "Start AdGuard again". */
export const ADGUARD_START_TEXT = "AdGuard's service is stopped. Starting it again also stops Sieve's routing, because the two cannot run together.";

/**
 * What the AdGuard action offers, from facts: pause while the engine waits
 * for AdGuard's running service; start again while that service is stopped
 * (whoever stopped it). Never shown when AdGuard is not installed.
 */
export function adguardOffer(e: EngineSlice): "pause" | "start" | null {
  const adguard = e.probe?.adguard;
  if (enginePhase(e) === "adguard" && adguard === "running") return "pause";
  return adguard === "stopped" ? "start" : null;
}

/** Split-tunnel VPNs the engine reported: their traffic bypasses Sieve, and the UI says so. */
export function splitTunnelText(e: EngineSlice): string | null {
  const names = engineStatus(e)?.split_tunnels ?? [];
  if (names.length === 0) return null;
  return `${names.join(", ")} sends some traffic around Sieve (a split-tunnel VPN). That traffic is not shown.`;
}

/** Share of flows the engine tied to an app, from its own counters; null before any flow. */
export function attribution(e: EngineSlice): number | null {
  const c = engineStatus(e)?.counters;
  return c && c.flows > 0 ? c.attributed / c.flows : null;
}

/** The engine's version, when it said it. */
export function engineVersion(e: EngineSlice): string | null {
  const pipe = e.probe?.pipe;
  return pipe?.kind === "welcome" ? pipe.engine_version : null;
}

/** The engine routes now: the app reads flows from it instead of the connection tables. */
export function engineRoutes(e: EngineSlice): boolean {
  return enginePhase(e) === "routing";
}
