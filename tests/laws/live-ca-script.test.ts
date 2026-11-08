/**
 * Law: the live CA script's decisions cannot print a PASS it did not see, and its
 * policy write changes only what it owns. Runs the script's own functions under
 * PowerShell, with nothing elevated and nothing touched.
 */
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { ROOT, hits, read, walk } from "./files";

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

describe("the slice 6 route", () => {
  const OFF = { ...POLICY, engine: false, sieving: false };
  const source = JSON.stringify(OFF).replaceAll("'", "''");

  it("ends with engine and sieving on, dropping nothing", () => {
    const written = JSON.parse(powershell(`New-InterceptionPolicyJson ('${source}' | ConvertFrom-Json)`));
    expect(written).toEqual({ ...OFF, revision: 8, https: true, engine: true, sieving: true });
  });

  it("believes only a status of this run", () => {
    const up = (status: string, revision: number) => powershell(`Test-InterceptionUp ('${status}' | ConvertFrom-Json) ${revision}`) === "True";
    const status = (revision: number, routes = true) => JSON.stringify({ routes_up: routes, policy: { revision, https: true, sieving: true } });
    expect(up(status(8), 8)).toBe(true);
    expect(up(status(7), 8), "the last run's file, routes up").toBe(false);
    expect(up(status(8, false), 8), "this run, no routes").toBe(false);
    expect(powershell("Test-InterceptionUp $null 8"), "no file").toBe("False");
    expect(powershell(`Get-PolicyRevision '${JSON.stringify({ revision: 8 })}'`)).toBe("8");
  });

  it("is what the script's own step writes, and what the runbook names", () => {
    const script = read("scripts/live/engine-ca.ps1");
    expect(script).toContain('"intercept" {');
    expect(script).toContain("New-InterceptionPolicyJson $policy");
    expect(script).toContain("Test-InterceptionUp (Read-Status) $want");
    const runbook = read("docs/live/engine-slice-6.md");
    expect(runbook).toContain("-Step intercept");
    expect(runbook).toContain("https.intercepted");
  });
});

describe("the HTTPS record tool", () => {
  const HTTPS_CHECKS = "scripts/live/https-record-checks.ps1";
  const run = (body: string) => execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference = 'Stop'; . '${HTTPS_CHECKS}'; ${body}`], { cwd: ROOT, encoding: "utf8" }).trim();
  const NAME = [1, 97, 7, 101, 120, 97, 109, 112, 108, 101, 0];
  const QUESTION = [...NAME, 0, 65, 0, 1];
  /** A reply to `QUESTION` with one record per rdata; its owner is a pointer back to the question. */
  const reply = (records: number[][]) => {
    const answers = records.flatMap((rdata) => [0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 1, 44, 0, rdata.length, ...rdata]);
    return [0, 7, 0x81, 0x80, 0, 1, 0, records.length, 0, 0, 0, 0, ...QUESTION, ...answers];
  };
  const read = (bytes: number[]) => JSON.parse(run(`@(Read-HttpsAnswers ([byte[]](${bytes.join(",")}))) | ConvertTo-Json -Compress -Depth 3`) || "[]");

  it("asks type 65, class IN, with no EDNS", () => {
    const asked = JSON.parse(run(`(New-HttpsQuery 'a.example.' 7) -join ','  | ForEach-Object { '[' + $_ + ']' }`));
    expect(asked).toEqual([0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...QUESTION]);
  });

  it("tells an answer with ech from one without", () => {
    const ALPN = [0, 1, 0, 3, 2, 104, 50];
    const ECH = [0, 5, 0, 3, 0xaa, 0xbb, 0xcc];
    expect(read(reply([[0, 1, 0, ...ALPN, ...ECH]]))).toEqual({ Priority: 1, Keys: [1, 5], Ech: true });
    expect(read(reply([[0, 2, 0, ...ALPN]]))).toEqual({ Priority: 2, Keys: [1], Ech: false });
  });

  it("reads past a target name, and finds no record in an empty answer", () => {
    expect(read(reply([[0, 1, 1, 98, 0, 0, 5, 0, 1, 9]]))).toEqual({ Priority: 1, Keys: [5], Ech: true });
    expect(read(reply([]))).toEqual([]);
  });
});

describe("every live script", () => {
  // Windows PowerShell 5.1 reads BOM-less UTF-8 as Windows-1252, so a policy written back
  // after a plain read garbles non-ASCII app names and rules, and an Off stops matching.
  it("reads the engine's JSON as UTF-8", () => {
    const plain = walk("scripts/live", [".ps1"]).flatMap((f) => hits(f, /Get-Content\b.*-Raw(?!.*-Encoding)/i).filter((l) => !/-Encoding\s+utf8.*-Raw/i.test(l)));
    expect(plain).toEqual([]);
  });
});

describe("the key checks", () => {
  const answer = (text: string, seenAsSystem: boolean) => powershell(`Get-KeyAnswer '${text}' $${seenAsSystem}`);
  const passes = (facts: string) => powershell(`Test-KeyFacts ${facts}`) === "True";

  // certutil's real answers on Windows Server 2025 (live run 2026-11-08): exit 0 every
  // time, and the same NTE_BAD_KEYSET line for a refused key and a missing one.
  const LOAD_FAILED = [
    "Microsoft Software Key Storage Provider:",
    "  Sieve root ee7388dceee344e1",
    "cuLoadKey: LoadKeys returned Keyset does not exist 0x80090016 (-2146893802 NTE_BAD_KEYSET) -- Sieve root ee7388dceee344e1",
    "CertUtil: -key command completed successfully.",
  ].join("\n");
  const LOADED = [
    "Microsoft Software Key Storage Provider:",
    "  Sieve root ee7388dceee344e1",
    "  d4aaa9317f3bffa093d0faa5b7470b5c_811ed7af-9c60-4692-ae69-c8e2e88f1d7a",
    "  ECDSA_P256",
    "  ECDSA",
    "CertUtil: -key command completed successfully.",
  ].join("\n");

  it("tells a missing key from a refused one by what SYSTEM saw, not by certutil's exit", () => {
    expect(answer(LOAD_FAILED, true), "SYSTEM opened it, the admin could not").toBe("refused");
    expect(answer(LOAD_FAILED, false), "nobody could open it").toBe("missing");
    expect(answer(LOADED, true), "certutil printed the key's algorithm").toBe("readable");
    expect(answer("CertUtil: -key command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED) Access is denied.", false)).toBe("refused");
    expect(answer("CertUtil: -key command FAILED: 0x80090010 (-2146893808 NTE_PERM) Access denied.", false)).toBe("refused");
    expect(answer("CertUtil: -key command FAILED: something else", true)).toBe("error");
  });

  it("sees an enabled backup privilege, which reads any key file", () => {
    const priv = (state: string) => powershell(`Test-BackupPrivilegeEnabled 'SeBackupPrivilege                         Back up files and directories                                      ${state}'`);
    expect(priv("Enabled")).toBe("True");
    expect(priv("Disabled")).toBe("False");
  });

  it("passes only what was seen as SYSTEM", () => {
    const facts = (policy: string, sids: string) => `([pscustomobject]@{ exists = $true; export_policy = '${policy}'; dacl_sids = @(${sids}) })`;
    expect(passes(facts("None", "'S-1-5-18'"))).toBe(true);
    expect(passes("([pscustomobject]@{ exists = $false })"), "a key SYSTEM did not find").toBe(false);
    expect(passes("$null"), "no answer is not a pass").toBe(false);
    expect(passes(facts("None", "")), "an empty DACL shows nothing").toBe(false);
    expect(passes(facts("AllowExport", "'S-1-5-18'"))).toBe(false);
    expect(passes(facts("None", "'S-1-5-18','S-1-5-32-544'")), "administrators too").toBe(false);
  });

  it("finds a key gone only when SYSTEM answered that it is", () => {
    const gone = (facts: string) => powershell(`Test-KeyGone ${facts}`) === "True";
    expect(gone("([pscustomobject]@{ exists = $false })")).toBe(true);
    expect(gone("$null"), "no answer is not gone").toBe(false);
    expect(gone("([pscustomobject]@{ exists = $true; export_policy = 'None'; dacl_sids = @('S-1-5-18') })")).toBe(false);
    const script = read("scripts/live/engine-ca.ps1");
    expect(script, "no leftover is judged from the admin's key listing").not.toMatch(/\$listing -match/);
  });

  it("writes a probe that names the key and parses", () => {
    const probe = powershell("New-KeyProbeScript 'Sieve root abc' 'C:\\out\\facts.json'");
    expect(probe).toContain("'Sieve root abc'");
    expect(probe).toContain("'C:\\out\\facts.json'");
    const errors = powershell(`$errs = $null; [void][Management.Automation.PSParser]::Tokenize((New-KeyProbeScript 'k' 'f'), [ref]$errs); $errs.Count`);
    expect(errors).toBe("0");
  });
});
