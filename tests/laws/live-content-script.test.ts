/**
 * Law: the content script's `-Lists`, given as slice 10's runbook writes it, reaches
 * the policy as the arm's ids. `powershell -File` hands a comma list to `[string[]]`
 * as one string, and the engine ignores an id it does not know, so one wrong line
 * here runs every arm with no lists. Runs only the script's pure half, nothing
 * elevated and nothing touched.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { armLists } from "../../scripts/live/youtube.mjs";
import { ROOT, read } from "./files";

const SCRIPT = "scripts/live/engine-content.ps1";
const CHECKS = "scripts/live/engine-content-checks.ps1";
const RUNBOOK = "docs/live/engine-slice-10.md";
const POWERSHELL_MS = 60_000;
const PARAM = "[string[]]$Lists";

describe("the lists the content script writes", () => {
  let dir: string;
  let probe: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "sieve-content-law-"));
    probe = join(dir, "probe.ps1");
    const checks = resolve(ROOT, CHECKS);
    writeFileSync(probe, `param(${PARAM})\n$ErrorActionPreference = 'Stop'\n. '${checks}'\n$policy = [pscustomobject]@{ revision = 1 }\nSet-PolicyLists $policy $Lists\n$policy | ConvertTo-Json -Depth 10\n`);
  });

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  /** The argument as `powershell -File` binds it, which is how the runbook calls it. */
  const written = (lists: string): { lists: string[] } =>
    JSON.parse(execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", probe, "-Lists", lists], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));

  it("the probe binds what the real script declares", () => {
    expect(read(SCRIPT)).toContain(PARAM);
  });

  it("the runbook's command gives the arm's ids, one each, not one joined id", { timeout: POWERSHELL_MS }, () => {
    const runbook = read(RUNBOOK);
    const lists = /engine-content\.ps1 -Step on -Lists (\S+)/.exec(runbook)?.[1];
    expect(lists).toBeDefined();
    expect(written(lists as string).lists).toEqual(armLists(fixture, "adguard"));
    const second = /`adguard\+ubo`, adds `(\S+)`/.exec(runbook)?.[1];
    expect(written(`${lists},${second}`).lists).toEqual(armLists(fixture, "adguard+ubo"));
  });

  it("spaces and stray commas fall away, and one id is still a list", { timeout: POWERSHELL_MS }, () => {
    expect(written("a, b ,,c,").lists).toEqual(["a", "b", "c"]);
    expect(written("a").lists).toEqual(["a"]);
  });

  it("a list of nothing is refused: it would run with no lists", { timeout: POWERSHELL_MS }, () => {
    expect(() => written(",")).toThrow();
  });

  it("the script writes lists through that one function", () => {
    const source = read(SCRIPT);
    expect(source).toContain("engine-content-checks.ps1");
    expect(source).toContain("Set-PolicyLists $policy $Lists");
    expect(source).not.toContain("@($Lists)");
  });
});
