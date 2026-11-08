/**
 * Tracking protection, the pure part: its options are the registry's `tracking`
 * section (each one a setting with its words, its level and what it can break)
 * and its level is derived from them by the one profile law (core/profiles), so
 * the level is never stored beside the options it summarises.
 *
 * Every option acts on decrypted traffic and requires the HTTPS switch. The
 * policy carries only those in force (`trackingInForce`): an option stored on
 * while that switch is off or unavailable is a wish, kept, never sent. Until the
 * engine carries them out the options themselves are unavailable (registry
 * `trackingOption`): none is in force, whatever its default, and no screen shows them.
 */
import { CUSTOM, inPreset, presetOf } from "./profiles";
import { SETTING_KEYS, TRACKING_LEVELS, isAvailable, settingDef, type SettingKey, type TrackingLevel } from "./settings/registry";

/** The options, in registry order. */
export const TRACKING_KEYS: readonly SettingKey[] = SETTING_KEYS.filter((k) => settingDef(k).section === "tracking");

/** Tracking protection is offered at all: its options share one availability (registry `trackingOption`). */
export const trackingOffered = () => TRACKING_KEYS.every(isAvailable);

/** What a person gets who changes nothing: the options' defaults. */
export const RECOMMENDED_TRACKING: TrackingLevel = "standard";

export const TRACKING_TEXT: Readonly<Record<TrackingLevel | typeof CUSTOM, { label: string; text: string }>> = {
  standard: { label: "Standard", text: "Stops the common ways sites follow you, without changing how they work." },
  strict: { label: "Strict", text: "Also hides where you came from and expires other sites' cookies. Some sign-ins and payments may need another try." },
  custom: { label: "Custom", text: "Your own choice of the options below." },
};

/** The name an option has in the policy's `tracking` (sieve_ipc::TRACKING_NAMES). */
export const trackingName = (key: SettingKey) => key.slice("tracking.".length);

/** The level the options are at, or Custom. `read` gives a setting's stored value. */
export function trackingLevel(read: (key: SettingKey) => unknown): TrackingLevel | typeof CUSTOM {
  return presetOf(
    TRACKING_LEVELS,
    TRACKING_KEYS.map((k) => ({ level: settingDef(k).preset ?? null, on: read(k) === true })),
  );
}

/** Every option's value at `level`. */
export function trackingValues(level: TrackingLevel): Record<string, boolean> {
  return Object.fromEntries(TRACKING_KEYS.map((k) => [k, inPreset(TRACKING_LEVELS, level, settingDef(k).preset ?? null)]));
}

/** The options the policy carries: available, on, and with the switch each requires on. `read` gives the value in force. */
export function trackingInForce(read: (key: SettingKey) => unknown): string[] {
  return TRACKING_KEYS.filter((k) => {
    const needs = settingDef(k).requires as SettingKey | undefined;
    return isAvailable(k) && read(k) === true && (needs === undefined || read(needs) === true);
  }).map(trackingName);
}
