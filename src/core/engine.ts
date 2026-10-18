/**
 * The filtering engine, the pure part: the store slice and what the UI says
 * about it, derived from facts only (plan 1.6.5: "Filtering is not running"
 * comes from facts, never assumed). The facts are `engine_probe`: the
 * Windows service's state and, while it runs, the engine's own answer on
 * its pipe.
 *
 * The slice has one writer, the engine controller (src/data/engine-controller.ts).
 */
import type { EngineProbe } from "@/data/protocol";

/** How often the engine is asked while Sieve is open (plan 1.6.5). */
export const ENGINE_POLL_MS = 2000;

/** The Engine block's anchor in Settings (Settings > Engine), and the link to it (Home's Engine tile). */
export const ENGINE_ANCHOR = "engine";
export const ENGINE_HREF = `/settings/#${ENGINE_ANCHOR}`;

export interface EngineSlice {
  /** Newest probe; null before the first answer or after a failed read. */
  probe: EngineProbe | null;
  /** Why the newest read failed; null after a good one. */
  error: string | null;
}

export const EMPTY_ENGINE: EngineSlice = { probe: null, error: null };

export const ENGINE_PHASES = [
  "checking",
  "unreadable",
  "not_installed",
  "not_running",
  "refused",
  "incompatible",
  "idle",
  "filtering",
] as const;
export type EnginePhase = (typeof ENGINE_PHASES)[number];

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
    case "welcome":
      return p.pipe.status.filtering ? "filtering" : "idle";
  }
}

/** The state in a few words (the Engine block's status line). */
export const ENGINE_STATE_TEXT: Record<EnginePhase, string> = {
  checking: "Checking",
  unreadable: "Unknown",
  not_installed: "Not installed",
  not_running: "Not running",
  refused: "Installed",
  incompatible: "Installed, needs an update",
  idle: "Installed, not filtering",
  filtering: "Filtering",
};

/** One sentence on what the facts mean; never claims filtering that is not happening. */
export function engineDetail(e: EngineSlice): string {
  const phase = enginePhase(e);
  const p = e.probe;
  const pipe = p?.pipe ?? null;
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
        : "The engine is installed, but its Windows service is not running. Nothing is filtered.";
    case "refused":
      return `The engine answered: ${pipe?.kind === "refused" ? pipe.message : ""}. This copy of Sieve is not the installed one, so it cannot read the engine's status.`;
    case "incompatible":
      return pipe?.kind === "incompatible"
        ? `This app and the engine speak different versions (the engine supports ${pipe.supported[0]} to ${pipe.supported[1]}). Reinstall Sieve so both match.`
        : "";
    case "idle":
      return "The engine runs and changes nothing: no traffic goes through it.";
    case "filtering":
      return "The engine is filtering this computer's traffic.";
  }
}

/** The engine's version, when it said it. */
export function engineVersion(e: EngineSlice): string | null {
  const pipe = e.probe?.pipe;
  return pipe?.kind === "welcome" ? pipe.engine_version : null;
}
