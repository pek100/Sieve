/**
 * The first-run guide, the pure part. Its steps change nothing on the network on
 * their own: they are words, facts, and the switches that change traffic, each
 * at its value in force. A switch changes only on the person's click, through
 * Settings' own write (the password gate, `requires` and the engine's locks
 * apply as on the Settings row). The other action, pausing AdGuard, is the
 * engine controller's, on the person's click too (plan D14).
 */
import { HTTPS_INVITE, engineInForce, enginePhase, httpsInForce, type EnginePhase, type EngineSlice } from "./engine";
import { REGISTRY, SETTING_KEYS, isAvailable, settingDef, type SettingKey } from "./settings/registry";

/** The setting the guide writes by itself, on Skip or Finish, and the only one: it changes no traffic. */
export const WELCOME_DONE = "startup.welcomeDone" satisfies SettingKey;

export const WELCOME_STEP_IDS = ["what", "switches", "https", "adguard"] as const;
export type WelcomeStepId = (typeof WELCOME_STEP_IDS)[number];

export interface WelcomeStep {
  id: WelcomeStepId;
  title: string;
  body: string;
}

/**
 * Offer the pause: AdGuard's service runs and the engine is installed. Unlike
 * `adguardOffer` it does not wait for the engine to be blocked, which needs the
 * routing switch on: the guide offers the pause whatever that switch says.
 */
export function welcomeAdguard(e: EngineSlice): boolean {
  const probe = e.probe;
  return probe !== null && probe.adguard === "running" && probe.service !== "missing";
}

/** Traffic-changing switches this build offers; the screen shows each at its value in force, as Settings does. */
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

/**
 * The switches step in words true of each state: a new install reaches the guide
 * with them on, an older one may have them off, and the engine may not answer.
 */
const SWITCHES_STEP: Record<SwitchesState, Pick<WelcomeStep, "title" | "body">> = {
  on: {
    title: "What Sieve changes on your network",
    body: "These switches change traffic. Each is on or off as shown and says what it does. Turning one off returns that part to normal. You can change them here or later in Settings.",
  },
  off: {
    title: "Your network is as it was",
    body: "These switches change traffic, and they are off. Each says what it does. You can turn them on here or later in Settings, and turning one off again returns that part to normal.",
  },
  unknown: {
    title: "These switches change traffic",
    body: "Each says what it does. Sieve cannot read the engine right now, so what is shown may not be what the engine holds, and they can be changed once it answers. Each says why.",
  },
};

/**
 * The steps for these facts. `keepAdguard`: the person is on that step, so it
 * stays when their pause makes the offer go away. `httpsShown`: the HTTPS switch
 * as the switches step shows it.
 */
export function welcomeSteps(e: EngineSlice, keepAdguard: boolean, switches: SwitchesState, httpsShown: boolean): WelcomeStep[] {
  const steps: WelcomeStep[] = [
    {
      id: "what",
      title: "Sieve shows which apps talk to the network",
      body: "It charts each app's connections on this computer. While its engine routes your traffic, it also closes connections to the hosts your filter lists and rules name.",
    },
    { id: "switches", ...SWITCHES_STEP[switches] },
  ];
  // What HTTPS filtering does and where to turn it on, in words and a link. Left
  // out while it is on: shown on in the switches step, or held on by the engine.
  if (!httpsShown && !httpsInForce(e)) steps.push({ id: "https", title: HTTPS_INVITE.title, body: HTTPS_INVITE.body });
  if (keepAdguard || welcomeAdguard(e)) {
    steps.push({
      id: "adguard",
      title: "AdGuard is running",
      body: "Sieve's engine routes nothing while AdGuard's service runs. You can leave it that way, or pause AdGuard now.",
    });
  }
  return steps;
}
