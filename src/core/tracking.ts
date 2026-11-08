/**
 * Tracking protection, the pure part: its options are the registry's `tracking`
 * section (each one a setting with its words, its level and what it can break)
 * and its level is derived from them by the one profile law (core/profiles), so
 * the level is never stored beside the options it summarises.
 *
 * Every option acts on decrypted traffic and requires the HTTPS switch, or page
 * filtering for those that live in the page. The policy carries only those in
 * force (`trackingInForce`): an option stored on while its switch is off or
 * unavailable is a wish, kept, never sent. An option is offered once its switch
 * is (registry `isAvailable`), so while HTTPS decryption waits for its live check
 * none is offered, whatever its default, and no screen shows them.
 * What each does in the engine, and why each level has what it has:
 * docs/plans/2026-11-09-tracking-protection.md.
 */
import { CUSTOM, inPreset, presetOf } from "./profiles";
import { RECOMMENDED_TRACKING_LEVEL, SETTING_KEYS, TRACKING_LEVELS, isAvailable, settingDef, type SettingKey, type TrackingLevel } from "./settings/registry";

/** The options, in registry order. */
export const TRACKING_KEYS: readonly SettingKey[] = SETTING_KEYS.filter((k) => settingDef(k).section === "tracking");

/**
 * Tracking protection is offered at all: the options a level turns on are, which
 * is when the HTTPS switch is. One that lives in the page waits for page filtering
 * too, and the block shows only those offered.
 */
export const trackingOffered = () => TRACKING_KEYS.filter((k) => settingDef(k).preset != null).every(isAvailable);

/** The options offered now, by level, mildest first; those in no level last. Registry order within one. */
export function offeredTrackingKeys(): SettingKey[] {
  const rank = (k: SettingKey) => {
    const p = settingDef(k).preset ?? null;
    return p === null ? TRACKING_LEVELS.length : TRACKING_LEVELS.indexOf(p);
  };
  return TRACKING_KEYS.filter(isAvailable).sort((a, b) => rank(a) - rank(b));
}

/** What a person gets who changes nothing: the options' defaults. */
export const RECOMMENDED_TRACKING: TrackingLevel = RECOMMENDED_TRACKING_LEVEL;

export const TRACKING_TEXT: Readonly<Record<TrackingLevel | typeof CUSTOM, { label: string; text: string }>> = {
  minimal: { label: "Minimal", text: "Asks sites not to track you and removes Chrome's tracking header. Nothing a site needs changes." },
  balanced: { label: "Balanced", text: "Also removes tracking codes from links and hides your searches from the sites you open, without changing how sites work." },
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
