/**
 * Law 12, the engine and the network rule (docs/plans/2026-10-17-https-filtering.md,
 * "Sieve off means a normal network"; slice 3). The engine is the one part of
 * Sieve that changes traffic, so what it may write is pinned by name:
 *
 * - Routes: no code path writes a persistent route. The only route write in
 *   the engine is `CreateIpForwardEntry2` in `route/apply.rs`, inside
 *   `add_route`, whose LUID is a `SieveLuid` (only the adapter the engine
 *   created hands one out, in `tun/device.rs`). The IP Helper API writes the
 *   active store only, so every route goes with the adapter and none
 *   survives a reboot; `route -p`, `New-NetRoute`, the persistent store, the
 *   legacy `CreateIpForwardEntry` and netsh are never named. The engine's
 *   Rust test `a_route_row_names_the_sieve_adapter_and_nothing_else` checks
 *   the row itself.
 * - DNS: nothing in the app or the engine touches DNS settings (adapter DNS
 *   servers, the registry's NameServer values, wintun-bindings' netsh and
 *   registry helpers). DNS is caught on the adapter by a host route instead.
 *
 * The probe (`src/bin/probe`) is the spike's developer tool, run by hand and
 * never bundled (`pnpm engine:build` builds `--bin sieve-engine` only); it is
 * held to the DNS half of the law.
 */
import { describe, expect, it } from "vitest";
import { hits, read, walk } from "./files";

const ENGINE = "engine/crates";
const PROBE = "engine/crates/sieve-engine/src/bin/probe/";
const APPLY = "engine/crates/sieve-engine/src/route/apply.rs";

const engineSources = () => walk(ENGINE, [".rs"]);
const product = () => engineSources().filter((f) => !f.startsWith(PROBE));

/** Every way to write a route that this repo could spell. */
const ROUTE_WRITES = /CreateIpForwardEntry2|CreateIpForwardEntry\b|SetIpForwardEntry2?|PersistentStore|New-NetRoute|route\s+(?:-p\s+)?add|netsh/i;

/** Every way to change DNS settings that this repo could spell. */
const DNS_WRITES = new RegExp(
  [
    "SetInterfaceDnsSettings",
    "DnsClientServerAddress",
    "Set-DnsClient",
    "set_dns_servers",
    "set_dns_via_registry",
    "NameServer",
    "netsh[^\\n]*dns",
    "Tcpip\\\\Parameters\\\\Interfaces",
    // wintun-bindings' helpers that shell out to netsh for addresses
    "\\.set_address\\(",
    "\\.set_gateway\\(",
    "\\.set_netmask\\(",
    "set_network_addresses_tuple",
  ].join("|"),
  "i",
);

const ETW = "engine/crates/sieve-engine/src/flow/etw.rs";
const NAT = "engine/crates/sieve-engine/src/flow/nat.rs";
const NAT_OS = "engine/crates/sieve-engine/src/flow/nat/os.rs";
const RUNNER = "engine/crates/sieve-engine/src/service/runner.rs";

const ETW_CONTROL = /\b(?:StartTraceW|ControlTraceW|EnableTraceEx2)\b/;
const WMI_QUERY = /\bExecQuery\b/;
/** What would make attribution change the system or outlive the engine. */
const ATTRIBUTION_WRITES = /Autologger|EVENT_TRACE_FILE_MODE|ExecMethod|PutInstance|New-NetNat|Add-NetNat|Remove-NetNat/i;

const STRING_LITERAL = /"(?:[^"\\\n]|\\.)*"/g;
const HARDCODED_VM = /wsl|ubuntu|cowork|hyper-v/i;

/** Comment lines say what is banned; only code counts. */
const code = (lines: string[]) => lines.filter((h) => !/^\S+:\d+: (\/\/|\*|\/\*)/.test(h));

describe("engine network law", () => {
  it("the only route write in the engine is CreateIpForwardEntry2 in route/apply.rs", () => {
    const writes = code(product().flatMap((f) => hits(f, ROUTE_WRITES)));
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.map((h) => h.split(":")[0])).toEqual(writes.map(() => APPLY));
    const calls = code(hits(APPLY, /CreateIpForwardEntry2\(/));
    expect(calls).toHaveLength(1);
  });

  it("that write is add_route on a SieveLuid, journalled first", () => {
    const src = read(APPLY);
    const body = src.match(/pub fn add_route\(journal: &Journal, luid: SieveLuid, prefix: Prefix\)[^{]*\{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(body.indexOf("journal.append")).toBeGreaterThan(-1);
    expect(body.indexOf("journal.append")).toBeLessThan(body.indexOf("CreateIpForwardEntry2"));
    expect(body).toContain("route_row(luid, prefix)");
    expect(src).toMatch(/pub fn route_row\(luid: SieveLuid, prefix: Prefix\)/);
    expect(src).toContain("row.InterfaceLuid = NET_LUID_LH { Value: luid.0 };");
    // Only the adapter the engine created mints a SieveLuid.
    const minted = code(engineSources().flatMap((f) => hits(f, /SieveLuid::of_created_adapter\(/)));
    expect(minted.map((h) => h.split(":")[0]).filter((f) => f !== APPLY)).toEqual(["engine/crates/sieve-engine/src/tun/device.rs"]);
  });

  it("nothing in the app or the engine touches DNS settings", () => {
    const files = [...walk("src", [".ts", ".tsx"]).filter((f) => !/\.test\.tsx?$/.test(f)), ...walk("src-tauri/src", [".rs"]), ...engineSources()];
    expect(files.length).toBeGreaterThan(80);
    expect(code(files.flatMap((f) => hits(f, DNS_WRITES)))).toEqual([]);
  });

  it("the patterns catch what they are for", () => {
    for (const bad of ["CreateIpForwardEntry2(&row)", "SetIpForwardEntry2(&row)", "route -p add 0.0.0.0", "New-NetRoute -PolicyStore PersistentStore", "netsh interface ipv4 add route"])
      expect(ROUTE_WRITES.test(bad), bad).toBe(true);
    for (const bad of ["adapter.set_dns_servers(&dns)", "set_dns_via_registry(&guid, &s)", "SetInterfaceDnsSettings(guid, &s)", "netsh interface ip set dns", "adapter.set_address(ip)", r`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`])
      expect(DNS_WRITES.test(bad), bad).toBe(true);
    for (const ok of ["DeleteIpForwardEntry2(&row)", "GetIpForwardTable2(AF_UNSPEC, &mut t)", "FirstDnsServerAddress", "Resolve-DnsName example.com"]) {
      expect(ROUTE_WRITES.test(ok) || DNS_WRITES.test(ok), ok).toBe(false);
    }
  });

  it("attribution only reads the system: its session lives in flow/etw.rs, its queries in flow/nat/os.rs, and nothing persists", () => {
    const owner = (pattern: RegExp, file: string) => {
      const found = code(product().flatMap((f) => hits(f, pattern)));
      expect(found.length, String(pattern)).toBeGreaterThan(0);
      expect(found.map((h) => h.split(":")[0]).filter((f) => f !== file), String(pattern)).toEqual([]);
    };
    owner(ETW_CONTROL, ETW);
    owner(WMI_QUERY, NAT_OS);
    expect(code(engineSources().flatMap((f) => hits(f, ATTRIBUTION_WRITES)))).toEqual([]);
    const session = read(ETW);
    expect(session).toContain("EVENT_TRACE_REAL_TIME_MODE");
    expect(session).not.toMatch(/EVENT_TRACE_FILE_MODE|LogFileMode = [^E]/);
  });

  it("both emergency exits stop the attribution session too: routing off means no session, even when recovery runs out", () => {
    const src = read(RUNNER);
    const trip = src.match(/impl Trip for ServiceTrip \{([\s\S]*?)\n\}/)?.[1] ?? "";
    const panic = src.match(/fn install_panic_cleanup\([^)]*\) \{([\s\S]*?)\n\}/)?.[1] ?? "";
    for (const exit of [trip, panic]) {
      expect(exit).toMatch(/emergency_cleanup\(\s*\|\|\s*clear_stale\([^\n]*\),\s*stop_stale\s*\)/);
      expect(exit.match(/\bclear_stale\(/g)).toHaveLength(1);
    }
  });

  it("those patterns catch what they are for", () => {
    for (const bad of ["StartTraceW(&mut h, name, p)", "ControlTraceW(h, name, p, c)", "EnableTraceEx2(h, &g, 1, 5, 0, 0, 0, None)"]) expect(ETW_CONTROL.test(bad), bad).toBe(true);
    expect(WMI_QUERY.test("services.ExecQuery(&wql, &q, flags, None)")).toBe(true);
    for (const bad of [
      r`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\X`,
      "EVENT_TRACE_FILE_MODE_SEQUENTIAL",
      "services.ExecMethod(&path, &m, 0, None, None)",
      "services.PutInstance(&o, 0, None)",
      "New-NetNat -Name x",
      "Add-NetNatStaticMapping",
      "Remove-NetNat -Name x",
    ]) {
      expect(ATTRIBUTION_WRITES.test(bad), bad).toBe(true);
    }
    for (const ok of ["ProcessTrace(&[t], None, None)", "SELECT * FROM MSFT_NetNatSession", "EVENT_TRACE_REAL_TIME_MODE"]) expect(ATTRIBUTION_WRITES.test(ok), ok).toBe(false);
  });

  it("no VM is named in the engine's attribution source: a name comes from the system", () => {
    const files = [ETW, NAT, NAT_OS, "engine/crates/sieve-engine/src/stack/attribution.rs", "engine/crates/sieve-engine/src/stack/book.rs"];
    for (const f of files) expect(read(f).length, f).toBeGreaterThan(0);
    const named = files.flatMap((f) => [...read(f).matchAll(STRING_LITERAL)].map((m) => m[0]).filter((s) => HARDCODED_VM.test(s)).map((s) => `${f}: ${s}`));
    expect(named).toEqual([]);
    for (const bad of ['"WSL"', '"wslhost.exe"', '"Ubuntu-24.04"', '"Cowork VM"', '"Hyper-V"']) expect(HARDCODED_VM.test(bad), bad).toBe(true);
    expect(HARDCODED_VM.test('"DevBox"')).toBe(false);
  });

  it("the bundle builds the engine binary only, never the probe", () => {
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.scripts["engine:build"]).toContain("--bin sieve-engine");
    expect(pkg.scripts["engine:build"]).not.toMatch(/--bins|--bin probe|--all-targets/);
  });
});

function r(s: TemplateStringsArray) {
  return s.raw.join("");
}
