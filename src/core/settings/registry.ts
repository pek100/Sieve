/**
 * Settings registry (primitive B5). Every setting is one entry here and
 * nowhere else. Settings screens, search, export, import, reset and the
 * data-switch gating are all derived from this list.
 *
 * Data switches: anything that would change traffic or the system is kind
 * "dataSwitch", defaults to false and names the live check that proves it
 * works on the real machine (a `live_*` test). The registry law enforces it.
 * No switch may write persistent system network state (DNS servers, routes,
 * proxy settings, firewall rules): Sieve off means a normal network.
 */
import { APP_STATES, type AppState } from "../policy";
import { parseUpstream } from "../upstream";

/**
 * 2: apps.levels became on/off per app. 3: filtering.systemDns is gone. 4: a
 * stored unavailable data switch is dropped, so it is off. 5: filtering.dns
 * and filtering.perApp are gone; filtering.upstreams holds encrypted upstreams
 * (see migrate.ts).
 */
export const SETTINGS_SCHEMA = 5;

/** Settings sections in the order the settings view shows them; a key's prefix is its section. */
export const SECTIONS = [
  { id: "appearance", label: "Appearance" },
  { id: "sampling", label: "Sampling" },
  { id: "startup", label: "Startup" },
  { id: "apps", label: "Apps" },
  { id: "filtering", label: "Filtering" },
] as const;

export type Section = (typeof SECTIONS)[number]["id"];

interface Base<T> {
  section: Section;
  label: string;
  help: string;
  default: T;
  /** Settings key of a data switch that must be on for this one to apply. */
  requires?: string;
  /** Only the desktop app can apply it (it talks to Windows through a Tauri plugin). */
  desktopOnly?: boolean;
  /**
   * Present: the setting is unavailable until what this names replaces it or
   * brings it back (a plan step, with the plan's path). It then has no row,
   * search, export or import, the UI that edits it is not shown, and it reads
   * as its default, so an unavailable data switch is never on. Absent:
   * available. Its code stays (see isAvailable).
   */
  unavailableUntil?: string;
}

/** Shape of one element of a map or list setting. `upstream`: an encrypted DNS upstream (see parseUpstream). */
export type ElementSpec = { type: "string" } | { type: "upstream" } | { type: "enum"; options: readonly string[] };

export function isValidElement(spec: ElementSpec, v: unknown): boolean {
  if (typeof v !== "string") return false;
  switch (spec.type) {
    case "string":
      return v.trim().length > 0;
    case "upstream":
      return parseUpstream(v) !== null;
    case "enum":
      return spec.options.includes(v);
  }
}

export interface EnumSetting<O extends string = string> extends Base<O> {
  kind: "enum";
  options: readonly O[];
}
export interface BooleanSetting extends Base<boolean> {
  kind: "boolean";
}
export interface NumberSetting extends Base<number> {
  kind: "number";
  min: number;
  max: number;
  step: number;
  unit: string;
}
export interface MapSetting<V> extends Base<Readonly<Record<string, V>>> {
  kind: "map";
  /** Shape of every value in the map. */
  of: ElementSpec;
}
export interface ListSetting<V> extends Base<readonly V[]> {
  kind: "list";
  /** Shape of every item in the list. */
  of: ElementSpec;
}
export interface DataSwitchSetting extends Base<false | boolean> {
  kind: "dataSwitch";
  /** Name of the ignored Rust/Playwright test that proves the switch on the real machine. */
  liveCheck: string;
  /**
   * The filtering engine carries it out (the app sends it with SetPolicy).
   * Then the row is locked whenever the engine cannot take a policy
   * (core/engine `engineLockReason`: not installed, not running, refused,
   * incompatible, unreadable, checking) and shows the engine's value in
   * force, never an unsent wish; a stored value waits, untouched, until the
   * engine can take it.
   */
  needsEngine?: true;
}

export type SettingDef =
  | EnumSetting
  | BooleanSetting
  | NumberSetting
  | MapSetting<unknown>
  | ListSetting<unknown>
  | DataSwitchSetting;

const enumSetting = <const O extends string>(d: Omit<EnumSetting<O>, "kind">): EnumSetting<O> => ({
  kind: "enum",
  ...d,
});

export const REGISTRY = {
  "appearance.theme": enumSetting({
    section: "appearance",
    label: "Theme",
    help: "Dark is tuned for the live chart. System follows Windows.",
    options: ["system", "light", "dark"],
    default: "dark",
  }),
  // The global state (policy GLOBAL_SWITCH). Static help cannot know the
  // build's facts, so it claims nothing about blocking: the Engine block derives that.
  "sampling.enabled": {
    kind: "boolean",
    section: "sampling",
    label: "Sieving",
    help: "On: Sieve charts which apps talk to the network. Off pauses it. What the engine filters is in Settings, under Engine.",
    default: true,
  } satisfies BooleanSetting,
  "sampling.intervalMs": {
    kind: "number",
    section: "sampling",
    label: "Sample every",
    help: "How often Sieve reads the connection tables.",
    default: 1000,
    min: 500,
    max: 10000,
    step: 500,
    unit: "ms",
  } satisfies NumberSetting,
  // Not a data switch: it changes no traffic, needs no admin and writes only
  // the current user's Run entry, through tauri-plugin-autostart, when the
  // user turns it on (declared exception, docs/conventions.md section 6).
  "startup.launchAtLogin": {
    kind: "boolean",
    section: "startup",
    label: "Launch at startup",
    help: "Start Sieve when you sign in to Windows. Adds Sieve to your own startup apps; off removes it.",
    default: false,
    desktopOnly: true,
  } satisfies BooleanSetting,
  // Key name kept from schema 1 (per-app levels); only "off" entries are stored now.
  "apps.levels": {
    kind: "map",
    section: "apps",
    label: "Apps turned off",
    help: "Apps Sieve leaves out of its charts, counts and history. Every other app is sieved.",
    default: {} as Readonly<Record<string, AppState>>,
    of: { type: "enum", options: APP_STATES },
  } satisfies MapSetting<AppState>,
  "apps.pinned": {
    kind: "list",
    section: "apps",
    label: "My apps",
    help: "Executables you added by hand. They show under Mine even when not running.",
    default: [] as readonly string[],
    of: { type: "string" },
  } satisfies ListSetting<string>,
  // The engine's switch (docs/plans/2026-10-17-https-filtering.md, slice 3):
  // on, the engine brings up its Wintun adapter and routes this computer's
  // traffic through itself. The app sends it to the engine (the engine controller, `SetPolicy`); off, the
  // engine has no adapter and no route. The live check is run by the user
  // (docs/live/engine-slice-3.md) and read back by the ignored test of its name.
  "filtering.engine": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Route traffic through the engine",
    help: "Sends this computer's traffic through Sieve's engine, so Home and Apps show each app's connections as the engine sees them. The Engine block below says what it filters. Off: the engine adds no adapter and no route, and your network is as it was.",
    default: false,
    liveCheck: "live_engine_full_route_relays_and_restores",
    needsEngine: true,
  } satisfies DataSwitchSetting,
  // Plan 1.4: the engine forwards every lookup encrypted, tried in order.
  "filtering.upstreams": {
    kind: "list",
    section: "filtering",
    label: "Upstream DNS servers",
    help: "Where the engine sends DNS lookups, encrypted, tried in order: DNS over HTTPS, TLS or QUIC. It never sends plain DNS.",
    default: ["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"] as readonly string[],
    of: { type: "upstream" },
  } satisfies ListSetting<string>,
  // Written by the log's row actions after a preview (core/log-actions).
  "filtering.userRules": {
    kind: "list",
    section: "filtering",
    label: "Your rules",
    help: "Filter rules you added from the log, in adblock syntax.",
    default: [] as readonly string[],
    of: { type: "string" },
  } satisfies ListSetting<string>,
  "filtering.exclusions": {
    kind: "list",
    section: "filtering",
    label: "Sites not decrypted",
    help: "Sites you chose from the log that Sieve leaves encrypted.",
    default: [] as readonly string[],
    of: { type: "string" },
  } satisfies ListSetting<string>,
} as const;

export type SettingKey = keyof typeof REGISTRY;

type Widen<T> = T extends string
  ? T
  : T extends boolean
    ? boolean
    : T extends number
      ? number
      : T;

export type SettingValue<K extends SettingKey> = (typeof REGISTRY)[K] extends EnumSetting<infer O>
  ? O
  : Widen<(typeof REGISTRY)[K]["default"]>;

export type SettingValues = { [K in SettingKey]: SettingValue<K> };

export const SETTING_KEYS = Object.keys(REGISTRY) as SettingKey[];

export function settingDef(key: SettingKey): SettingDef {
  return REGISTRY[key] as SettingDef;
}

export function defaultValue<K extends SettingKey>(key: K): SettingValue<K> {
  return REGISTRY[key].default as SettingValue<K>;
}

export function isSettingKey(key: string): key is SettingKey {
  return Object.prototype.hasOwnProperty.call(REGISTRY, key);
}

/**
 * Can the user see and change this setting in this build? The one place the
 * answer comes from: the settings document, export, import, search and the
 * Settings view all ask it. No key is unavailable today (law 11).
 */
export function isAvailable(key: SettingKey): boolean {
  return settingDef(key).unavailableUntil === undefined;
}

/** Does the filtering engine carry this setting out (a data switch declared `needsEngine`)? */
export function needsEngine(key: SettingKey): boolean {
  const def = settingDef(key);
  return def.kind === "dataSwitch" && def.needsEngine === true;
}

/** Does `value` have the shape the registry declares for `key`? */
export function isValidValue(key: SettingKey, value: unknown): boolean {
  const def = settingDef(key);
  switch (def.kind) {
    case "enum":
      return typeof value === "string" && def.options.includes(value);
    case "boolean":
    case "dataSwitch":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number" && Number.isFinite(value) && value >= def.min && value <= def.max;
    case "map":
      return (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        Object.values(value).every((v) => isValidElement(def.of, v))
      );
    case "list":
      return Array.isArray(value) && value.every((v) => isValidElement(def.of, v));
  }
}
