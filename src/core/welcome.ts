/**
 * The first-run guide, the pure part. Its steps change nothing on the network by
 * construction: they are words and read-only facts. The one action, pausing
 * AdGuard, is the existing engine controller's, on the person's click (plan D14).
 */
import { engineInForce, enginePhase, type EnginePhase, type EngineSlice } from "./engine";
import { REGISTRY, SETTING_KEYS, isAvailable, settingDef, type SettingKey } from "./settings/registry";

/** The setting the guide writes, and the only one. */
export const WELCOME_DONE = "startup.welcomeDone" satisfies SettingKey;

export const WELCOME_STEP_IDS = ["what", "switches", "adguard"] as const;
export type WelcomeStepId = (typeof WELCOME_STEP_IDS)[number];

export interface WelcomeStep {
  id: WelcomeStepId;
  title: string;
  body: string;
}

/**
 * Offer the pause: AdGuard's service runs and the engine is installed. Unlike
 * `adguardOffer` it does not wait for the engine to be blocked, which needs the
 * routing switch on, and the guide never turns that on.
 */
export function welcomeAdguard(e: EngineSlice): boolean {
  const probe = e.probe;
  return probe !== null && probe.adguard === "running" && probe.service !== "missing";
}

/** Traffic-changing switches this build offers, for reading only; the screen shows each at its value in force. */
export function dataSwitchSummary(): { key: SettingKey; label: string; help: string }[] {
  return SETTING_KEYS.filter((k) => settingDef(k).kind === "dataSwitch" && isAvailable(k)).map((key) => ({
    key,
    label: REGISTRY[key].label,
    help: REGISTRY[key].help,
  }));
}

export type SwitchesState = "off" | "on" | "unknown";

/** Phases where the engine may be up but did not say what it holds. */
const ENGINE_UNSAID: readonly EnginePhase[] = ["checking", "unreadable", "refused", "incompatible"];

/** What the switches, each at its value in force, add up to. */
export function switchesState(inForce: readonly boolean[], e: EngineSlice): SwitchesState {
  if (inForce.includes(true)) return "on";
  return engineInForce(e) === null && ENGINE_UNSAID.includes(enginePhase(e)) ? "unknown" : "off";
}

/** The switches step in words true of each state: an install can reach the guide with one on. */
const SWITCHES_STEP: Record<SwitchesState, Pick<WelcomeStep, "title" | "body">> = {
  off: {
    title: "Your network stays as it is",
    body: "Only these can change traffic. They are off, and this guide leaves them off. Turn one on in Settings if you want it.",
  },
  on: {
    title: "This guide leaves your network as you set it",
    body: "Only these can change traffic. A switch shown on is on now, and this guide changes none of them. You can change them in Settings.",
  },
  unknown: {
    title: "This guide leaves your network as it is",
    body: "Only these can change traffic, and this guide changes none of them. Sieve cannot read the engine right now, so what is shown may not be what the engine holds. Settings says why.",
  },
};

/**
 * The steps for these facts. `keepAdguard`: the person is on that step, so it
 * stays when their pause makes the offer go away.
 */
export function welcomeSteps(e: EngineSlice, keepAdguard: boolean, switches: SwitchesState): WelcomeStep[] {
  const steps: WelcomeStep[] = [
    {
      id: "what",
      title: "Sieve shows which apps talk to the network",
      body: "It charts each app's connections on this computer, and blocks nothing until you turn the engine on. The engine then closes connections to the hosts your filter lists and rules name.",
    },
    { id: "switches", ...SWITCHES_STEP[switches] },
  ];
  if (keepAdguard || welcomeAdguard(e)) {
    steps.push({
      id: "adguard",
      title: "AdGuard is running",
      body: "Sieve's engine routes nothing while AdGuard's service runs. You can leave it that way, or pause AdGuard now.",
    });
  }
  return steps;
}
