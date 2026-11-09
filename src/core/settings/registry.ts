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
import { customListsFit, isCustomList, type CustomList } from "../custom-lists";
import { APP_STATES, type AppState } from "../policy";
import { ALLOWLIST_TEXT, checkRuleLine, normalizeDomain } from "../rules";
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
  { id: "notifications", label: "Notifications" },
  { id: "filters", label: "Filter lists" },
  { id: "tracking", label: "Tracking protection" },
  { id: "password", label: "Password" },
] as const;

/** Tracking protection's levels, mildest first (the scale of core/profiles), named as the filter profiles are. */
export const TRACKING_LEVELS = ["minimal", "balanced", "strict"] as const;
export type TrackingLevel = (typeof TRACKING_LEVELS)[number];
/** What a person gets who changes nothing; every option's default derives from it (core/tracking re-exports it). */
export const RECOMMENDED_TRACKING_LEVEL: TrackingLevel = "balanced";

export type Section = (typeof SECTIONS)[number]["id"];

interface Base<T> {
  section: Section;
  label: string;
  help: string;
  default: T;
  /** Settings key of a switch (a data switch, or a boolean) that must be on for this one to apply. */
  requires?: string;
  /** Only the desktop app can apply it (it talks to Windows through a Tauri plugin). */
  desktopOnly?: boolean;
  /**
   * Present: the setting is unavailable until what this names replaces it or
   * brings it back (a plan step, with the plan's path). It then has no row,
   * search, export or import, the UI that edits it is not shown, and it reads
   * as its default, so an unavailable data switch is never on. Absent: available
   * once the setting it `requires` is (see isAvailable). Its code stays.
   */
  unavailableUntil?: string;
  /** A record of what happened, not a preference: "Reset every setting" leaves it. Its own row can still change it. */
  keptByResetAll?: true;
  /** A tracking protection: the lowest level that turns it on, null for none (its default is on exactly at Balanced, the recommended level). */
  preset?: TrackingLevel | null;
  /** What turning it on can break, in plain words, shown beside it. */
  breaks?: string;
}

/**
 * Shape of one element of a map or list setting. `upstream`: an encrypted DNS
 * upstream (see parseUpstream). `rule`: one user rule or comment line. `domain`: a
 * normalized host name. So an import cannot smuggle in a trusted scriptlet or a
 * junk host: the registry refuses it.
 */
export type ElementSpec = { type: "string" } | { type: "upstream" } | { type: "rule" } | { type: "domain" } | { type: "enum"; options: readonly string[] } | { type: "customList" };

export function isValidElement(spec: ElementSpec, v: unknown): boolean {
  // `customList`: one of the person's own lists, the engine's own rule (core/custom-lists).
  if (spec.type === "customList") return isCustomList(v);
  if (typeof v !== "string") return false;
  switch (spec.type) {
    case "string":
      return v.trim().length > 0;
    case "upstream":
      return parseUpstream(v) !== null;
    case "rule": {
      const kind = checkRuleLine(v).kind;
      return kind !== "blank" && kind !== "error";
    }
    case "domain": {
      const d = normalizeDomain(v);
      return d.ok && d.host === v;
    }
    case "enum":
      return spec.options.includes(v);
  }
}

/** The person's sentence for why this list value is refused, when its element shape has one. */
export function listValueProblem(key: SettingKey, value: unknown): string | null {
  const def = settingDef(key);
  if (def.kind !== "list" || !Array.isArray(value)) return null;
  for (const v of value) {
    if (isValidElement(def.of, v) || typeof v !== "string") continue;
    if (def.of.type === "rule") {
      const check = checkRuleLine(v);
      if (check.kind === "error") return check.message;
    }
    if (def.of.type === "domain") {
      const d = normalizeDomain(v);
      if (!d.ok) return d.error;
    }
  }
  return null;
}

/** The largest policy the engine takes (`sieve_ipc::MAX_POLICY_BYTES`; tests/laws/engine-ipc.test.ts ties them). */
export const MAX_POLICY_BYTES = 512 * 1024;
const KIB = 1024;

/**
 * The settings the engine controller sends whole in its one policy, and how much
 * of the engine's limit each group may use. The groups leave room for the
 * switches, the list selection and the JSON around them, so settings within
 * these budgets always fit. A setting over its budget is refused where it is
 * saved or imported: a policy that does not fit would hold back the off switch.
 */
export const POLICY_BUDGETS: readonly { keys: readonly SettingKey[]; bytes: number; what: string }[] = [
  {
    keys: ["filtering.userRules", "filtering.blockedDomains", "filtering.allowedDomains", "filtering.exclusions"],
    bytes: MAX_POLICY_BYTES - 64 * KIB,
    what: "Your rules, blocklist, allowlist and undecrypted sites",
  },
  { keys: ["apps.levels"], bytes: 32 * KIB, what: "The apps you turned off" },
  { keys: ["filters.custom"], bytes: 16 * KIB, what: "Your own filter lists" },
];

export type PolicyBudget = (typeof POLICY_BUDGETS)[number];

/** What these values of a budget's settings take up in a policy, in bytes. */
export function budgetBytes(budget: PolicyBudget, read: (key: SettingKey) => unknown): number {
  return new TextEncoder().encode(JSON.stringify(budget.keys.map(read))).length;
}

/** The person's sentence for a budget this many bytes would break. */
export function budgetProblem(budget: PolicyBudget, bytes: number): string {
  const kb = (n: number) => Math.ceil(n / KIB);
  return `${budget.what} would come to ${kb(bytes)} KB, more than the ${kb(budget.bytes)} KB the engine can hold, so this was not saved. Remove some and try again.`;
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
  /** What one entry is called, for summaries ("3 apps"). */
  noun: string;
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

/** The plan step that brings interception, without which the HTTPS switch means nothing. */
const ENGINE_SLICE_6 = "engine slice 6 (docs/plans/2026-10-17-https-filtering.md)";
/** The plan step whose live check opens rewriting pages to the user. */
const ENGINE_SLICE_9 = "engine slice 9 (docs/plans/2026-10-17-https-filtering.md)";
const enumSetting = <const O extends string>(d: Omit<EnumSetting<O>, "kind">): EnumSetting<O> => ({
  kind: "enum",
  ...d,
});

/**
 * One tracking protection (plan rows 26 to 30, docs/plans/2026-11-09-tracking-protection.md),
 * carried out by the engine. Each acts on decrypted requests, so each requires
 * the HTTPS switch; one that lives in the page's script requires page filtering,
 * which is what writes it. The engine controller sends only those in force. Its
 * default is derived from its level: on exactly when Balanced, the recommended
 * level, turns it on, so the defaults are Balanced (core/tracking).
 *
 * Available once the switch it requires is (isAvailable): until then none is
 * shown, searched, imported or sent, and a stored wish is kept unread.
 */
const trackingOption = (d: { label: string; help: string; preset: TrackingLevel | null; breaks?: string; inPage?: true }): BooleanSetting => {
  const { inPage, ...rest } = d;
  return {
    kind: "boolean",
    section: "tracking",
    requires: inPage ? "filtering.content" : "filtering.https",
    default: d.preset !== null && TRACKING_LEVELS.indexOf(d.preset) <= TRACKING_LEVELS.indexOf(RECOMMENDED_TRACKING_LEVEL),
    ...rest,
  };
};

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
    help: "On: Sieve charts which apps talk to the network and, while the engine routes, closes their connections to blocked hosts. Off pauses both. What the engine filters is in Settings, under Engine.",
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
    help: "Apps Sieve leaves out of its charts, counts and history. While the engine routes, their traffic is relayed untouched. Every other app is sieved.",
    default: {} as Readonly<Record<string, AppState>>,
    of: { type: "enum", options: APP_STATES },
    noun: "app",
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
  // traffic through itself; it relays each flow or closes one to a blocked host. The
  // app sends it to the engine (the engine controller, `SetPolicy`); off, the
  // engine has no adapter and no route. The live check is run by the user
  // (docs/live/engine-slice-3.md) and read back by the ignored test of its name.
  "filtering.engine": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Route traffic through the engine",
    help: "Sends this computer's traffic through Sieve's engine, so Home and Apps show each app's connections as the engine sees them and connections to blocked hosts are closed. The Engine block below says what it filters. Off: the engine adds no adapter and no route, and your network is as it was.",
    default: false,
    liveCheck: "live_engine_full_route_relays_and_restores",
    needsEngine: true,
  } satisfies DataSwitchSetting,
  // The user's own rules (B6), sent whole in the engine's policy and edited on
  // the Filters page. They beat the lists both ways.
  "filtering.blockedDomains": {
    kind: "list",
    section: "filtering",
    label: "Blocklist",
    help: "Hosts the engine closes for every sieved app, with their subdomains, whatever the filter lists say. Edited under Filters.",
    default: [] as readonly string[],
    of: { type: "domain" },
  } satisfies ListSetting<string>,
  "filtering.allowedDomains": {
    kind: "list",
    section: "filtering",
    label: "Allowlist",
    help: `${ALLOWLIST_TEXT} Edited under Filters.`,
    default: [] as readonly string[],
    of: { type: "domain" },
  } satisfies ListSetting<string>,
  // The root certificate (docs/plans/2026-10-17-https-filtering.md, slice 5).
  // Hidden until interception exists: it "cannot be on without slice 6". The
  // app therefore sends off, and the live check drives it with the app closed
  // (docs/live/engine-slice-5.md). Settings' Certificate group turns it off.
  "filtering.https": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Decrypt HTTPS traffic",
    help: "Installs Sieve's own certificate on this computer so the engine can filter inside HTTPS. Off: the certificate is removed from Windows and Firefox.",
    default: false,
    liveCheck: "live_https_intercepts_public_and_passes_floor",
    requires: "filtering.engine",
    needsEngine: true,
    unavailableUntil: ENGINE_SLICE_6,
  } satisfies DataSwitchSetting,
  // Rewriting decrypted pages (slice 9). Hidden until its live check has run; the
  // app sends off, and docs/live/engine-slice-9.md drives it with the app closed.
  "filtering.content": {
    kind: "dataSwitch",
    section: "filtering",
    label: "Filter inside pages",
    help: "Hides page elements and runs the lists' page fixes on decrypted pages. Off: pages arrive exactly as the site sent them.",
    default: false,
    liveCheck: "live_content_injects_into_test_page",
    requires: "filtering.https",
    needsEngine: true,
    unavailableUntil: ENGINE_SLICE_9,
  } satisfies DataSwitchSetting,
  // Plan 1.4: the engine forwards every lookup encrypted, tried in order.
  "filtering.upstreams": {
    kind: "list",
    section: "filtering",
    label: "Upstream DNS servers",
    help: "Where the engine sends DNS lookups, encrypted, tried in order: DNS over HTTPS, TLS or QUIC. Only these servers, never a plain one.",
    default: ["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"] as readonly string[],
    of: { type: "upstream" },
  } satisfies ListSetting<string>,
  // The owner's decision (2026-11-06): encrypted by default, plain DNS only by
  // this choice, never as a fallback. Sent as the policy's `plain_dns`. TENSION:
  // it changes traffic yet is no data switch, whose default must be off: here
  // the default is the engine's safe behaviour and off is the user's to pick.
  "filtering.dnsEncryption": {
    kind: "boolean",
    section: "filtering",
    label: "Encrypt DNS lookups",
    help: "On: the engine sends the names of the sites you visit to the servers above, encrypted. Off: it sends them in plain text to your network's own DNS server, as Windows does without Sieve, and anyone on the network can see them. Some hotel and airport Wi-Fi needs it off to show its sign-in page.",
    default: true,
  } satisfies BooleanSetting,
  // The owner's decision (2026-11-09): "Setting, on by default". Sent as the
  // policy's `skip_dns_capture` only when off, so an engine from before it never
  // sees the field at the default. It needs encryption: with plain DNS there is
  // nothing to encrypt, the engine does not catch Windows' lookups, and the row
  // is locked with the reason (`requires`) rather than hidden.
  "filtering.dnsClientCapture": {
    kind: "boolean",
    section: "filtering",
    label: "Also encrypt Windows' own lookups",
    help: "Windows' built-in lookups also go through Sieve's encrypted DNS, so the network can't read them. Off: Windows sends them to your network's DNS server in plain text, as it does without Sieve.",
    breaks:
      "Names of nearby PCs found without DNS, and short names that don't exist, answer about 7 s slower. Hotel and café Wi-Fi sign-in pages may not open until you turn this off or sign in.",
    default: true,
    requires: "filtering.dnsEncryption",
  } satisfies BooleanSetting,
  // Written by the Filters page's editor and the log's row actions after a
  // preview (core/log-actions), and sent whole in the engine's policy.
  "filtering.userRules": {
    kind: "list",
    section: "filtering",
    label: "Your rules",
    help: "Rules you wrote under Filters or added from the log, in the same language as the filter lists.",
    default: [] as readonly string[],
    of: { type: "rule" },
  } satisfies ListSetting<string>,
  // Sent in the policy, the `user` layer of the engine's exclusion store; read while `filtering.https` is on.
  "filtering.exclusions": {
    kind: "list",
    section: "filtering",
    label: "Sites not decrypted",
    help: "Sites you added here or from the log that Sieve leaves encrypted. The list is under Not decrypted, below.",
    default: [] as readonly string[],
    of: { type: "string" },
  } satisfies ListSetting<string>,
  // The first-run guide is finished or skipped. Off shows it again at the next
  // open (hooks/use-welcome decides once per run), so it never takes over mid-run.
  "startup.welcomeDone": {
    kind: "boolean",
    section: "startup",
    label: "Welcome guide finished",
    help: "Off shows the welcome guide the next time Sieve opens.",
    default: false,
    keptByResetAll: true,
  } satisfies BooleanSetting,
  // Not a data switch: it changes no traffic. On asks Windows for permission first.
  "notifications.desktop": {
    kind: "boolean",
    section: "notifications",
    label: "Desktop notifications",
    help: "Tell you when the engine stops after repeated failures or sites may not load, while Sieve's window is not in front.",
    default: false,
    desktopOnly: true,
  } satisfies BooleanSetting,
  // Only differences from a list's own default are stored (core/filter-lists).
  // The engine controller turns them into the policy's `lists`.
  "filters.lists": {
    kind: "map",
    section: "filters",
    label: "Lists changed",
    help: "Filter lists you changed from their default. The engine downloads and applies the ones that are on, while it runs.",
    default: {} as Readonly<Record<string, string>>,
    of: { type: "enum", options: ["on", "off"] },
    noun: "list",
  } satisfies MapSetting<string>,
  // The person's own lists, sent whole as the policy's `custom_lists`. A list by
  // address is downloaded and judged by the engine; one from a file is kept by it.
  "filters.custom": {
    kind: "list",
    section: "filters",
    label: "Your own lists",
    help: "Filter lists you added by their address or from a file, under Filters. The engine downloads the ones by address, keeps the ones from files, and applies those that are on, without the trusted scriptlets the built-in lists may use.",
    default: [] as readonly CustomList[],
    of: { type: "customList" },
  } satisfies ListSetting<CustomList>,
  // Keys are the names in the policy's `tracking` (sieve_ipc::TRACKING_NAMES), in
  // its order, which is append-only; the block shows them by level.
  "tracking.gpc": trackingOption({
    label: "Ask sites not to track you",
    help: "Sends the Global Privacy Control and Do Not Track signals with every request, which sites that honour them treat as a no to selling or sharing what you do.",
    preset: "minimal",
  }),
  "tracking.searchQueries": trackingOption({
    label: "Hide your searches from the sites you open",
    help: "Other sites are told only which site sent you, never the page, so a site you open from a search is not told what you searched for.",
    preset: "balanced",
  }),
  "tracking.clientData": trackingOption({
    label: "Remove Chrome's tracking header",
    help: "Takes out the X-Client-Data header Chrome adds to requests to Google's sites, which can tell your browser apart from others.",
    preset: "minimal",
  }),
  "tracking.referrer": trackingOption({
    label: "Hide which page you came from",
    help: "Other sites are not told which page sent you to them.",
    preset: "strict",
    breaks: "Some downloads, payment pages and sign-ins check where you came from and may refuse to load.",
  }),
  "tracking.thirdPartyCookies": trackingOption({
    label: "Expire other sites' cookies after an hour",
    help: "Cookies that other sites set from inside the page you are on are kept for an hour at most, so they cannot follow you for long. The site you open keeps its own cookies, however you got there.",
    preset: "strict",
    breaks: "Comments, video players and sign-in buttons from other sites may ask you to sign in again, and so may a site that signs you in through another of its own domains.",
  }),
  "tracking.webRtc": trackingOption({
    label: "Block WebRTC",
    help: "Stops pages finding your real network address through WebRTC, even behind a VPN.",
    preset: null,
    breaks: "Video calls, voice chat and screen sharing in the browser stop working.",
    inPage: true,
  }),
  "tracking.push": trackingOption({
    label: "Block push notifications",
    help: "Sites cannot send you notifications through the browser.",
    preset: null,
    breaks: "Notifications from sites you chose to hear from stop too, such as web mail and chat.",
    inPage: true,
  }),
  "tracking.location": trackingOption({
    label: "Block location requests",
    help: "Sites cannot ask the browser where you are.",
    preset: null,
    breaks: "Maps, delivery and weather sites cannot find where you are.",
    inPage: true,
  }),
  "tracking.queryParams": trackingOption({
    label: "Remove tracking codes from links",
    help: "Takes campaign tags and click codes such as utm_source and fbclid out of the address of each page you open, so the site cannot tell which ad, mail or post sent you.",
    preset: "balanced",
  }),
  "tracking.firstPartyCookies": trackingOption({
    label: "Expire every site's own cookies after an hour",
    help: "The cookies of the site you are on are deleted after an hour too, so it cannot recognise you on your next visit.",
    preset: null,
    breaks: "Every site signs you out after an hour and forgets your settings and your basket.",
  }),
  "password.idleMinutes": {
    kind: "number",
    section: "password",
    label: "Lock again after",
    help: "With a password set, Sieve locks settings again after this long without a click or a key press.",
    default: 15,
    min: 5,
    max: 60,
    step: 5,
    unit: "min",
  } satisfies NumberSetting,
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
 * Settings view all ask it. A setting is unavailable by its own
 * `unavailableUntil`, or because the setting it requires is: what needs a switch
 * this build does not offer could never act (law 11). `filtering.https` and
 * `filtering.content` are unavailable today, and with them the tracking
 * protections that require them.
 */
export function isAvailable(key: SettingKey): boolean {
  return unavailableUntil(key) === null;
}

/** What a setting waits for: its own plan step, else the one of the setting it requires; null when available. */
export function unavailableUntil(key: SettingKey): string | null {
  const d = settingDef(key);
  if (d.unavailableUntil !== undefined) return d.unavailableUntil;
  return d.requires !== undefined && isSettingKey(d.requires) ? unavailableUntil(d.requires) : null;
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
      // The engine refuses an empty resolver list: an empty list never means plain DNS, so it means nothing.
      if (def.of.type === "upstream" && Array.isArray(value) && value.length === 0) return false;
      if (!Array.isArray(value) || !value.every((v) => isValidElement(def.of, v))) return false;
      // The engine refuses a policy with too many own lists or an id twice, and with it every later change.
      return def.of.type !== "customList" || customListsFit(value as CustomList[]);
  }
}
