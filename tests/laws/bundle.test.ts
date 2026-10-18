/**
 * Law 10, the per-machine bundle (plan 1.5): the installer is NSIS, per
 * machine (Program Files, which only admins can write: a service binary in a
 * user-writable folder would be a privilege escalation), the engine is built
 * before bundling, and the hooks call only verbs the engine has, uninstall
 * on a real uninstall and restore (stop only) on an update.
 */
import { describe, expect, it } from "vitest";
import { read } from "./files";

const conf = JSON.parse(read("src-tauri/tauri.conf.json"));
const hooks = read("src-tauri/windows/hooks.nsh");
const engineService = read("engine/crates/sieve-engine/src/service/mod.rs");
const pkg = JSON.parse(read("package.json"));

const macro = (name: string) => hooks.match(new RegExp(`!macro ${name}([\\s\\S]*?)!macroend`))?.[1] ?? "";
const verbs = (body: string) => [...body.matchAll(/\$\{SIEVE_ENGINE_EXE\}" (\w+)'/g)].map((m) => m[1]);

describe("bundle law", () => {
  it("is one NSIS installer, per machine, with Sieve's hooks", () => {
    expect(conf.bundle.targets).toEqual(["nsis"]);
    expect(conf.bundle.windows.nsis.installMode).toBe("perMachine");
    expect(conf.bundle.windows.nsis.installerHooks).toBe("windows/hooks.nsh");
  });

  it("builds the engine before bundling, and the hook embeds that build", () => {
    expect(conf.build.beforeBuildCommand).toContain("pnpm engine:build");
    expect(pkg.scripts["engine:build"]).toContain("--release --manifest-path engine/Cargo.toml -p sieve-engine --bin sieve-engine");
    expect(hooks).toContain(String.raw`engine\target\release\${SIEVE_ENGINE_EXE}`);
  });

  it("each hook runs the verb it must, and only verbs the engine has", () => {
    expect(verbs(macro("NSIS_HOOK_PREINSTALL"))).toEqual(["restore"]);
    expect(verbs(macro("NSIS_HOOK_POSTINSTALL"))).toEqual(["install"]);
    expect(verbs(macro("NSIS_HOOK_PREUNINSTALL"))).toEqual(["restore", "uninstall"]);
    expect(macro("NSIS_HOOK_PREUNINSTALL")).toMatch(/\$UpdateMode = 1[\s\S]*restore[\s\S]*\$\{Else\}[\s\S]*uninstall/);
    for (const verb of ["install", "uninstall", "restore"]) expect(engineService).toContain(`"${verb}" => Ok(Verb::`);
  });
});
