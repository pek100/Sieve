/**
 * Law: the live CA script's decisions cannot print a PASS it did not see, and its
 * policy write changes only what it owns. Runs the script's own functions under
 * PowerShell, with nothing elevated and nothing touched.
 */
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { ROOT } from "./files";

const CHECKS = "scripts/live/engine-ca-checks.ps1";

function powershell(body: string): string {
  const script = `$ErrorActionPreference = 'Stop'; . '${CHECKS}'; ${body}`;
  return execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], { cwd: ROOT, encoding: "utf8" }).trim();
}

const POLICY = {
  revision: 7,
  engine: true,
  sieving: true,
  off_apps: ["chrome"],
  lists: ["adguard-dns"],
  https: false,
  user_rules: "||x.example^",
  domain_lists: [{ domain: "a.example", kind: { deep: ["kept"] }, single: ["one"] }],
};

describe("the policy the script writes", () => {
  const written = (on: boolean) => {
    const source = JSON.stringify(POLICY).replaceAll("'", "''");
    return JSON.parse(powershell(`New-HttpsPolicyJson ('${source}' | ConvertFrom-Json) $${on}`));
  };

  it("changes the switch and the revision and nothing else", () => {
    expect(written(true)).toEqual({ ...POLICY, revision: 8, https: true });
  });

  it("adds the switch to a policy older than it", () => {
    expect(JSON.parse(powershell(`New-HttpsPolicyJson ('{"revision":1,"engine":true}' | ConvertFrom-Json) $false`))).toEqual({ revision: 2, engine: true, https: false });
  });
});

describe("the key checks", () => {
  const answer = (text: string, exit: number) => powershell(`Get-KeyAnswer '${text}' ${exit}`);
  const passes = (facts: string) => powershell(`Test-KeyFacts ${facts}`) === "True";

  it("tells a missing key from a refused one", () => {
    expect(answer("CertUtil: -key command FAILED: 0x80090016 (-2146893802 NTE_BAD_KEYSET) Keyset does not exist", 1)).toBe("missing");
    expect(answer("CertUtil: -key command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED) Access is denied.", 1)).toBe("refused");
    expect(answer("CertUtil: -key command FAILED: 0x80090010 (-2146893808 NTE_PERM) Access denied.", 1)).toBe("refused");
    expect(answer("CertUtil: something else", 1)).toBe("error");
    expect(answer("Export Policy", 0)).toBe("readable");
  });

  it("passes only what was seen as SYSTEM", () => {
    const facts = (policy: string, sids: string) => `([pscustomobject]@{ export_policy = '${policy}'; dacl_sids = @(${sids}) })`;
    expect(passes(facts("None", "'S-1-5-18'"))).toBe(true);
    expect(passes("$null"), "no answer is not a pass").toBe(false);
    expect(passes(facts("None", "")), "an empty DACL shows nothing").toBe(false);
    expect(passes(facts("AllowExport", "'S-1-5-18'"))).toBe(false);
    expect(passes(facts("None", "'S-1-5-18','S-1-5-32-544'")), "administrators too").toBe(false);
  });

  it("writes a probe that names the key and parses", () => {
    const probe = powershell("New-KeyProbeScript 'Sieve root abc' 'C:\\out\\facts.json'");
    expect(probe).toContain("'Sieve root abc'");
    expect(probe).toContain("'C:\\out\\facts.json'");
    const errors = powershell(`$errs = $null; [void][Management.Automation.PSParser]::Tokenize((New-KeyProbeScript 'k' 'f'), [ref]$errs); $errs.Count`);
    expect(errors).toBe("0");
  });
});
