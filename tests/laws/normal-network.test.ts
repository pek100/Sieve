/**
 * Law 8, Sieve off means a normal network (the user, 2026-10-18, after
 * "Point Windows at Sieve" left a rebooted PC with no DNS: "remove the Point
 * Windows at Sieve feature; the engine will replace it with something that
 * can't break the network"). Sieve never writes persistent system network
 * state: DNS servers, persistent routes, proxy settings, firewall rules that
 * outlive the process. Everything Sieve changes disappears by itself when
 * Sieve stops, crashes, is uninstalled or the PC reboots.
 *
 * Statically: neither the app (src) nor its Rust side (src-tauri/src) names
 * a call or tool that writes those, and nothing elevates. The settings
 * switch that did it is gone, and a stored value of it never survives a load.
 */
import { describe, expect, it } from "vitest";
import { normalizeDoc } from "@/core/settings/document";
import { RETIRED_KEYS } from "@/core/settings/migrate";
import { SETTINGS_SCHEMA, SETTING_KEYS } from "@/core/settings/registry";
import { hits, walk } from "./files";

/**
 * Persistent network writes and elevation, by the names code would have to
 * spell: Windows APIs, PowerShell cmdlets, command-line tools, the UAC verb.
 */
const WRITES = new RegExp(
  [
    // DNS servers
    "Set-DnsClientServerAddress",
    "SetInterfaceDnsSettings",
    "DnsClientServerAddress",
    // routes (persistent or not, the app has no business adding them)
    "CreateIpForwardEntry2?",
    "SetIpForwardEntry2?",
    "route\\s+(?:-p\\s+)?add",
    "New-NetRoute",
    // proxy settings
    "WinHttpSetDefaultProxyConfiguration",
    "InternetSetOption",
    "ProxyServer",
    // firewall
    "INetFwPolicy2",
    "FwpmFilterAdd0",
    "New-NetFirewallRule",
    "advfirewall",
    // the registry, the tool that wraps all of it, and elevation
    "RegSetValueEx",
    "RegSetKeyValue",
    // netsh, except a read (`netsh ... show ...`)
    "netsh(?![^\\n]*\\bshow\\b)",
    "ShellExecuteEx",
    '"runas"',
  ].join("|"),
  "i",
);

const sources = () => [
  ...walk("src", [".ts", ".tsx"]).filter((f) => !/\.test\.tsx?$/.test(f)),
  ...walk("src-tauri/src", [".rs"]),
];

describe("normal network law", () => {
  it("no code in src or src-tauri/src writes system network state or elevates", () => {
    const files = sources();
    expect(files.length).toBeGreaterThan(50);
    expect(files.flatMap((f) => hits(f, WRITES))).toEqual([]);
  });

  it("the pattern catches what it is for", () => {
    for (const bad of [
      "Set-DnsClientServerAddress -InterfaceIndex 7",
      "unsafe { ShellExecuteExW(&mut info) }",
      'let verb = wide("runas");',
      "netsh interface ip set dns",
      "netsh advfirewall firewall add rule",
      "CreateIpForwardEntry2(&row)",
      "route -p add 0.0.0.0",
      "RegSetValueExW(key, ...)",
    ])
      expect(WRITES.test(bad), bad).toBe(true);
    for (const ok of ["GetAdaptersAddresses", "read_adapters()", "IShellItemImageFactory", "RegGetValueW", "netsh int ipv4 show excludedportrange protocol=udp"])
      expect(WRITES.test(ok), ok).toBe(false);
  });

  it("the Windows DNS switch is gone, and a stored value of it is dropped on load, on or off", () => {
    expect(RETIRED_KEYS).toContain("filtering.systemDns");
    for (const k of RETIRED_KEYS) expect(SETTING_KEYS as readonly string[]).not.toContain(k);
    for (const on of [true, false]) {
      const doc = normalizeDoc({ schema: 2, values: { "filtering.systemDns": on, "appearance.theme": "light" } });
      expect(doc).toEqual({ schema: SETTINGS_SCHEMA, values: { "appearance.theme": "light" } });
    }
    // Written by schema 1 too.
    expect(normalizeDoc({ schema: 1, values: { "filtering.systemDns": true } }).values).toEqual({});
  });
});
