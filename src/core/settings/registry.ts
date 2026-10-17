/**
 * Settings registry (primitive B5). Every setting is one entry here and
 * nowhere else. Settings screens, search, export, import, reset and the
 * data-switch gating are all derived from this list.
 *
 * Data switches: anything that would change traffic or the system is kind
 * "dataSwitch", defaults to false and names the live check that proves it
 * works on the real machine (a `live_*` test). The registry law enforces it.
 */
import { isUpstream } from "../dns";
import { LEVELS, type Level } from "../policy";

export const SETTINGS_SCHEMA = 1;

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
}

/** Shape of one element of a map or list setting. `upstream`: a DNS server address (see isUpstream). */
export type ElementSpec = { type: "string" } | { type: "upstream" } | { type: "enum"; options: readonly string[] };

export function isValidElement(spec: ElementSpec, v: unknown): boolean {
  if (typeof v !== "string") return false;
  switch (spec.type) {
    case "string":
      return v.trim().length > 0;
    case "upstream":
      return isUpstream(v);
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
  /** Why this build cannot turn the switch on, said to the user. Absent: the switch works. */
  unavailable?: string;
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
  "sampling.enabled": {
    kind: "boolean",
    section: "sampling",
    label: "Sieving",
    help: "Read which apps have open connections, once per interval. Read only; nothing is blocked.",
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
  "apps.levels": {
    kind: "map",
    section: "apps",
    label: "Per-app level",
    help: "Off, watch or sieve, per app. Apps not listed use watch.",
    default: {} as Readonly<Record<string, Level>>,
    of: { type: "enum", options: LEVELS },
  } satisfies MapSetting<Level>,
  "apps.pinned": {
    kind: "list",
    section: "apps",
    label: "My apps",
    help: "Executables you added by hand. They show under Mine even when not running.",
    default: [] as readonly string[],
    of: { type: "string" },
  } satisfies ListSetting<string>,
  // DNS filtering is system wide: every Windows lookup reaches the proxy
  // through the DNS Client service, so it cannot tell apps apart.
  "filtering.dns": {
    kind: "dataSwitch",
    section: "filtering",
    label: "DNS filtering",
    help: "Blocks ad and tracker domains for every app on this computer, once Windows uses Sieve for DNS. Runs a DNS filter on this computer with the AdGuard DNS filter list.",
    default: false,
    liveCheck: "live_dns_filter_resolves_blocked_domain",
  } satisfies DataSwitchSetting,
  "filtering.upstreams": {
    kind: "list",
    section: "filtering",
    label: "Upstream DNS servers",
    help: "Where DNS filtering sends the lookups it does not block, tried in order. Applies the next time DNS filtering starts.",
    default: ["1.1.1.1", "9.9.9.9"] as readonly string[],
    of: { type: "upstream" },
  } satisfies ListSetting<string>,
  // The one place Sieve changes the system: a backup is written first and
  // Windows asks for administrator rights (src-tauri/src/sysdns).
  "filtering.systemDns": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Windows uses Sieve for DNS",
    help: "Points every active network adapter at Sieve (127.0.0.1 and ::1) after saving a backup of its DNS servers. Windows asks for administrator rights. Off restores the backup.",
    default: false,
    liveCheck: "live_system_dns_points_at_sieve",
    requires: "filtering.dns",
  } satisfies DataSwitchSetting,
  "filtering.perApp": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Per-app filtering",
    help: "Filter some apps and not others: the sieve level on Apps.",
    default: false,
    liveCheck: "live_per_app_filter_blocks_one_app",
    unavailable:
      "Telling which app made a lookup needs a network driver, which Sieve does not have. DNS filtering applies to every app.",
  } satisfies DataSwitchSetting,
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

/** Why this build cannot turn a data switch on (its `unavailable`), or null. */
export function unavailableReason(key: string): string | null {
  if (!isSettingKey(key)) return null;
  const d = settingDef(key);
  return d.kind === "dataSwitch" ? (d.unavailable ?? null) : null;
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
