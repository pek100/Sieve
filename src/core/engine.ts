/**
 * The filtering engine, the pure part: the store slice and what the UI says
 * about it, derived from facts only (plan 1.6.5: "Filtering is not running"
 * comes from facts, never assumed). The facts are `engine_probe`: the
 * Windows service's state and, while it runs, the engine's own answer on
 * its pipe (sieve-ipc Status: policy, blocker, split tunnels, counters and,
 * from slice 4, the per-list filter facts).
 *
 * An engine that routes with no rule applied blocks nothing: it is "Routing
 * traffic". Only rules the engine reports applied make it "Filtering hosts".
 * Whether anything is blocked is its own fact (`status.blocking`): routing with
 * no list compiled yet closes nothing, and the copy must not claim it does.
 *
 * The slice has one writer, the engine controller (src/data/engine-controller.ts).
 */
import type { CertState, CertStatus, EngineBlocker, EngineProbe, EngineStatus, EngineUpdate, FirefoxTrust, ListFact } from "@/data/protocol";

/** An update state that says nothing: no answer, or a missing or broken one. */
export const NO_UPDATE_NEWS: EngineUpdate = { kind: "not_configured" };

/** How often the engine is asked while Sieve is open (plan 1.6.5). */
export const ENGINE_POLL_MS = 2000;

/** The data switch that routes traffic through the engine (registry key; UI reads it from here). */
export const ENGINE_SWITCH = "filtering.engine";

/** The Engine block's anchor in Settings (Settings > Engine), and the link to it (Home's Engine tile). */
export const ENGINE_ANCHOR = "engine";
export const ENGINE_HREF = `/settings/#${ENGINE_ANCHOR}`;

/** The data switch that holds a root certificate (registry key; UI reads it from here). Off removes it. */
export const HTTPS_SWITCH = "filtering.https";
/** The Certificate group's anchor in Settings. */
export const CERTIFICATE_ANCHOR = "certificate";

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
  /** Why the last AdGuard stop or start, policy change or update request failed; null after a good one. */
  actionError?: string | null;
  /** Why `filtering.upstreams` did not reach the engine; null after a good read or send. */
  dnsError?: string | null;
  /** The root certificate as the engine last said; null while it cannot be asked. */
  cert?: CertStatus | null;
  /** Why the newest certificate read failed; null after a good one. */
  certError?: string | null;
  /** Why the user's last Reinstall failed; null after a good one. */
  certActionError?: string | null;
  /** An update request on its way to the engine. */
  requestingUpdate?: boolean;
}

export const EMPTY_ENGINE: EngineSlice = { probe: null, error: null, adguard: null, actionError: null, cert: null, certError: null, certActionError: null };

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
  "filtering",
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

/** The lists the engine reports, in its order; empty when it reports none. */
export function engineLists(e: EngineSlice): readonly ListFact[] {
  return engineStatus(e)?.filter?.lists ?? [];
}

const appliedRules = (lists: readonly ListFact[]) => lists.reduce((sum, l) => sum + l.applied, 0);

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
      if (s.filtering) return appliedRules(s.filter?.lists ?? []) > 0 ? "filtering" : "routing";
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
  filtering: "Filtering hosts",
  adguard: "Waiting for AdGuard",
  vpn: "Paused for a VPN",
  crash_loop: "Stopped after repeated failures",
  setup_failed: "Could not start",
};

/** The exact words of the pause offer (the user's decision: the UI says exactly what happens). */
export const ADGUARD_PAUSE_TEXT =
  "Pausing AdGuard asks its Windows service (Adguard Service) to stop. Windows asks you to approve it. AdGuard stops protecting this computer until you turn its protection on in AdGuard's own window or restart the computer.";

/** The text after a pause: the service stays StopPending, so there is no Start button, and this says what resumes it. */
export const ADGUARD_PAUSED_TEXT =
  "AdGuard is paused: its service is stopping and it no longer filters this computer. To turn it back on, use AdGuard's own window or restart the computer. Sieve steps aside when AdGuard filters again.";

/** Phases whose detail is a problem the user should read. */
export const ENGINE_PROBLEMS: ReadonlySet<EnginePhase> = new Set<EnginePhase>([
  "unreadable",
  "refused",
  "incompatible",
  "crash_loop",
  "setup_failed",
]);

const count = (n: number, one: string, many: string) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** What the filtering engine applies, from its own facts. */
function filteringDetail(e: EngineSlice): string {
  const lists = engineLists(e);
  const scope = engineStatus(e)?.decrypting === true ? "to host names and to the HTTPS it decrypts" : "to host names only";
  return `The engine applies ${count(appliedRules(lists), "rule", "rules")} from ${count(lists.length, "list", "lists")} ${scope}. Apps you turned off pass through untouched.`;
}

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
    case "filtering":
      return filteringDetail(e);
    case "adguard":
      return (
        "AdGuard is filtering this computer, and two filters would capture each other's connections. Sieve routes nothing while AdGuard filters; your network works as usual." +
        (p?.adguard === "stopping" ? " Sieve checks again every few seconds. If this stays, turn protection off in AdGuard's own window." : "")
      );
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
 * The engine ran its AdGuard check and found no interception: it routes with no
 * blocker, or the blocker is a VPN (AdGuard wins over a VPN). Read from the
 * blocker and not the phase, because routes stay up for seconds after the engine
 * publishes a blocker, and the phase still says routing then. Everything else
 * gives no verdict: the switch is off, the engine did not answer, the check
 * itself failed, or the engine answered a new policy before its first check.
 */
function adguardCleared(e: EngineSlice): boolean {
  const s = engineStatus(e);
  if (!engineTakesPolicy(e) || s?.policy.engine !== true) return false;
  return s.blocker ? s.blocker.kind === "vpn" : s.filtering;
}

/**
 * What the AdGuard action offers, from facts: pause while the engine waits
 * for AdGuard's running service; start again while that service is stopped
 * (whoever stopped it); "paused" (words only, `sc start` cannot resume it) for
 * a service stuck stopping once the engine found it no longer intercepts.
 * Never shown when AdGuard is not installed.
 */
export function adguardOffer(e: EngineSlice): "pause" | "start" | "paused" | null {
  const adguard = e.probe?.adguard;
  if (adguard === "running") return enginePhase(e) === "adguard" ? "pause" : null;
  if (adguard === "stopped") return "start";
  return adguard === "stopping" && adguardCleared(e) ? "paused" : null;
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

/**
 * The same share of host flows only, reported beside it once any flow was
 * forwarded; the gate stays the rate of all flows. Null before any host flow
 * (every flow forwarded divides by nothing).
 */
export function hostAttribution(e: EngineSlice): number | null {
  const c = engineStatus(e)?.counters;
  if (!c) return null;
  const hostFlows = c.flows - c.forwarded;
  return hostFlows > 0 ? (c.attributed - c.forwarded_named) / hostFlows : null;
}

/** The certificate's state in words (plan 8.1). The engine derives the state; the app never recomputes it. */
export const CERT_STATE_TEXT: Record<CertState, string> = {
  not_installed: "Not installed",
  installed: "Installed",
  expires_soon: "Expires soon",
  removal_pending: "Removal pending",
};
/** What the Certificate group says with no answer from the engine. */
export const CERT_STATE_UNKNOWN = "Unknown";

/** Firefox and the root, in words. `not_using_windows` is a policy someone else set to off: never a claim of trust. */
export const FIREFOX_TEXT: Record<FirefoxTrust, string> = {
  not_installed: "Not installed",
  uses_windows: "Uses Windows certificates",
  not_using_windows: "Does not use Windows certificates",
};

/** A root is installed, from the engine's own state. */
export function certInstalled(cert: CertStatus | null | undefined): boolean {
  return cert?.state === "installed" || cert?.state === "expires_soon";
}

/** The engine holds `filtering.https` on (its Status's policy), so it can take a Reinstall. */
export function httpsInForce(e: EngineSlice): boolean {
  return engineStatus(e)?.policy.https === true;
}

/** Where signed updates stand; nothing to say when the engine did not answer or said nothing. */
export function engineUpdate(e: EngineSlice): EngineUpdate {
  return engineStatus(e)?.update ?? NO_UPDATE_NEWS;
}

/** What the Engine block shows about updates. */
export interface UpdateNotice {
  text: string;
  /** Read as a problem. */
  problem: boolean;
  /** The one button, when one is offered: `RequestUpdate` means this in this state. */
  action: string | null;
}

export const CHECK_AGAIN = "Check again";
export const INSTALL_UPDATE = "Install update";

/** What is said about updates, or null for the states that show nothing. Never installs unasked. */
export function updateNotice(update: EngineUpdate): UpdateNotice | null {
  switch (update.kind) {
    case "current":
      return { text: "Sieve is up to date.", problem: false, action: CHECK_AGAIN };
    case "available":
      return {
        text: `Sieve ${update.version} is available. Installing it stops the engine for a few seconds and may close this window. Your network works as usual.`,
        problem: false,
        action: INSTALL_UPDATE,
      };
    case "applying":
      return { text: `Installing Sieve ${update.version}. The engine restarts by itself; your network works as usual.`, problem: false, action: null };
    case "stale":
      return { text: "The update host's list of versions has expired, so Sieve did not use it. Nothing was changed.", problem: true, action: CHECK_AGAIN };
    case "failed":
      return { text: `Sieve could not check for updates: ${update.message}`, problem: false, action: CHECK_AGAIN };
    case "refused":
      return { text: `Sieve refused an update and changed nothing: ${update.message}`, problem: true, action: CHECK_AGAIN };
    case "rolled_back":
      return { text: `Sieve ${update.version} did not start, so the previous version is back. Your network works as usual.`, problem: true, action: CHECK_AGAIN };
    case "not_configured":
    case "idle":
    case "checking":
      return null;
  }
}

/** The Home banner, for what the user should know without opening Settings. */
export function updateBanner(update: EngineUpdate): string | null {
  if (update.kind === "available") return `Sieve ${update.version} is available. Install it in Settings > Filtering.`;
  if (update.kind === "rolled_back") return `Sieve ${update.version} did not start, so the previous version is back. Your network works as usual.`;
  return null;
}

/** The engine's version, when it said it. */
export function engineVersion(e: EngineSlice): string | null {
  const pipe = e.probe?.pipe;
  return pipe?.kind === "welcome" ? pipe.engine_version : null;
}

/** The engine routes now, filtering or not: the app reads flows and its log from it. */
export function engineRoutes(e: EngineSlice): boolean {
  const phase = enginePhase(e);
  return phase === "routing" || phase === "filtering";
}
