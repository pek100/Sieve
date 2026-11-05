/**
 * Law 10, the per-machine bundle (plan 1.5 and 7): the installer is NSIS,
 * per machine, the engine is built before bundling, and the hooks call only
 * verbs the engine has, uninstall on a real uninstall and restore (stop only)
 * on an update, always through the engine the service is registered with.
 *
 * The install folder (2026-10-18, live finding: E:\Sieve inherited
 * "Authenticated Users: Modify" and the engine runs as SYSTEM): the user may
 * pick any folder, and the pre-install hook locks it before the first file is
 * copied (owner first, then inheritance off, then the grants), refuses a
 * non-empty folder without Sieve's marker, and writes the marker only into a
 * folder it checked empty after locking. The marker name and the refusal's
 * exit code are the engine's (service::image, service::mod). The engine test
 * `the_hooks_icacls_lines_give_the_install_lock` runs the icacls lines.
 */
import { describe, expect, it } from "vitest";
import { read } from "./files";

const conf = JSON.parse(read("src-tauri/tauri.conf.json"));
const hooks = read("src-tauri/windows/hooks.nsh");
const engineService = read("engine/crates/sieve-engine/src/service/mod.rs");
const engineImage = read("engine/crates/sieve-engine/src/service/image.rs");
const engineAcl = read("engine/crates/sieve-engine/src/service/acl.rs");
const pkg = JSON.parse(read("package.json"));

const block = (open: string, close: string) => (name: string) =>
  hooks.match(new RegExp(`${open} ${name}\\b([\\s\\S]*?)${close}`))?.[1] ?? "";
const macro = block("!macro", "!macroend");
const fn = block("Function", "FunctionEnd");
const verbs = (body: string) => [...body.matchAll(/"\$SieveEngine" (\w+)'/g)].map((m) => m[1]);
const icacls = [...fn("SieveLockInstallDir").matchAll(/!insertmacro SIEVE_ICACLS '([^']*)'/g)].map((m) => m[1]);

describe("bundle law", () => {
  it("is one NSIS installer, per machine, with Sieve's hooks", () => {
    expect(conf.bundle.targets).toEqual(["nsis"]);
    expect(conf.bundle.windows.nsis.installMode).toBe("perMachine");
    expect(conf.bundle.windows.nsis.installerHooks).toBe("windows/hooks.nsh");
    // Tauri's own template: a custom one would fork it.
    expect(conf.bundle.windows.nsis.template).toBeUndefined();
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

  it("stops and removes the engine the service is registered with, wherever it is", () => {
    expect(hooks).toContain(String.raw`!define SIEVE_SERVICE_KEY "SYSTEM\CurrentControlSet\Services\sieve-engine"`);
    expect(macro("SIEVE_REGISTERED_ENGINE")).toContain('ReadRegStr $SieveEngine HKLM "${SIEVE_SERVICE_KEY}" "ImagePath"');
    for (const hook of ["NSIS_HOOK_PREINSTALL", "NSIS_HOOK_PREUNINSTALL"]) {
      expect(macro(hook).trim().startsWith("!insertmacro SIEVE_REGISTERED_ENGINE"), hook).toBe(true);
    }
    expect(macro("NSIS_HOOK_POSTUNINSTALL")).toContain('Delete "$SieveEngine"');
  });

  it("a failed uninstall verb keeps the engine its rerun needs, and says how to finish", () => {
    const pre = macro("NSIS_HOOK_PREUNINSTALL");
    expect(pre).toMatch(/" uninstall'\s+Pop \$0\s+\$\{If\} \$0 != 0\s+StrCpy \$SieveEngineKept 1\s+MessageBox/);
    const post = macro("NSIS_HOOK_POSTUNINSTALL");
    expect(post).toMatch(/\$\{AndIf\} \$SieveEngineKept != 1\s+Delete "\$SieveEngine"/);
    // No delete of an engine file sits outside that guard.
    expect(post.indexOf("Delete")).toBeGreaterThan(post.indexOf("$SieveEngineKept"));
  });

  it("locks the install folder before any file is copied, owner first", () => {
    const pre = macro("NSIS_HOOK_PREINSTALL");
    expect(pre).not.toMatch(/\bFile\b/);
    expect(pre.indexOf("restore")).toBeLessThan(pre.indexOf("Call SieveLockInstallDir"));
    expect(icacls).toEqual([
      "/setowner *S-1-5-32-544",
      "/inheritance:r",
      "/remove:g *S-1-1-0 *S-1-5-11 *S-1-5-32-545 *S-1-5-4 *S-1-3-0",
      "/grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX",
    ]);
    expect(macro("SIEVE_ICACLS")).toContain(String.raw`"$SYSDIR\icacls.exe" "$INSTDIR" ` + "${ARGS}");
    expect(macro("SIEVE_ICACLS")).toMatch(/\$0 != 0[\s\S]*Abort/);
    // The Rust constant the engine test compares the result with.
    expect(engineAcl).toContain('INSTALL_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"');
  });

  it("refuses a non-empty folder it did not prepare, and marks only a folder it checked empty after locking", () => {
    const lock = fn("SieveLockInstallDir");
    const first = lock.indexOf("Call SieveForeignEntry");
    const lockAt = lock.indexOf("SIEVE_ICACLS");
    const recheck = lock.indexOf("Call SieveForeignEntry", lockAt);
    const marker = lock.indexOf('FileOpen $0 "$INSTDIR\\${SIEVE_MARKER}" w');
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(lockAt);
    expect(recheck).toBeGreaterThan(lockAt);
    expect(marker).toBeGreaterThan(recheck);
    expect(lock.match(/SIEVE_REFUSE_FOREIGN\s+Abort/g)).toHaveLength(2);
    expect(fn("SieveForeignEntry")).toContain('${IfNot} ${FileExists} "$INSTDIR\\${SIEVE_MARKER}"');
    // The directory page checks the choice on Next too.
    expect(hooks).toContain("!define MUI_DIRECTORYPAGE_VERIFYONLEAVE");
    expect(fn(".onVerifyInstDir")).toMatch(/SIEVE_REFUSE_FOREIGN\s+Abort/);
  });

  it("bundles the pinned Wintun and its licence beside the engine, never from the repo", () => {
    const tun = read("engine/crates/sieve-engine/src/tun/mod.rs");
    const pin = tun.match(/pub const WINTUN_SHA256: &str = "([0-9a-f]{64})";/)?.[1];
    expect(pin).toBe("e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce");
    expect(read("scripts/wintun.mjs")).toContain("pub const WINTUN_SHA256");
    expect(pkg.scripts["engine:build"]).toMatch(/&& node scripts\/wintun\.mjs$/);
    expect(hooks).toContain(String.raw`engine\target\release\${SIEVE_WINTUN_DLL}`);
    const licence = hooks.match(/!define SIEVE_WINTUN_LICENSE "([^"]+)"/)?.[1];
    expect(tun).toContain(`pub const WINTUN_LICENSE: &str = "${licence}";`);
    expect(read("engine/vendor/wintun/LICENSE.txt")).toMatch(/^Prebuilt Binaries License/);
    const post = macro("NSIS_HOOK_POSTINSTALL");
    // Copied before the install verb runs its folder check over every file beside the exe.
    expect(post.indexOf('File "/oname=${SIEVE_WINTUN_DLL}"')).toBeGreaterThan(-1);
    expect(post.indexOf('File "/oname=${SIEVE_WINTUN_DLL}"')).toBeLessThan(post.indexOf('" install\''));
    expect(macro("NSIS_HOOK_POSTUNINSTALL")).toContain('Delete "$INSTDIR\\${SIEVE_WINTUN_DLL}"');
    expect(read(".gitignore")).toContain("/engine/**/*.dll");
  });

  it("adds the emergency restore shortcut, elevated, and removes it on uninstall", () => {
    const post = macro("NSIS_HOOK_POSTINSTALL");
    expect(post).toContain(`CreateShortCut "\${SIEVE_RESTORE_LINK}" "$SYSDIR\\cmd.exe" '/k ""$SieveEngine" restore"'`);
    expect(post).toMatch(/FileSeek \$1 0x15 SET[\s\S]*IntOp \$2 \$2 \| 0x20[\s\S]*FileWriteByte \$1 \$2/);
    expect(hooks).toContain(String.raw`!define SIEVE_RESTORE_LINK "$SMPROGRAMS\Sieve - restore network.lnk"`);
    expect(macro("NSIS_HOOK_POSTUNINSTALL")).toContain('Delete "${SIEVE_RESTORE_LINK}"');
  });

  it("names the engine's marker and refusal exit code", () => {
    const marker = hooks.match(/!define SIEVE_MARKER "([^"]+)"/)?.[1];
    expect(engineImage).toContain(`pub const MARKER_FILE: &str = "${marker}";`);
    const code = hooks.match(/!define SIEVE_EXIT_UNSAFE_FOLDER (\d+)/)?.[1];
    expect(engineService).toContain(`pub const EXIT_UNSAFE_FOLDER: i32 = ${code};`);
    expect(macro("NSIS_HOOK_POSTINSTALL")).toContain("${If} $0 = ${SIEVE_EXIT_UNSAFE_FOLDER}");
    expect(macro("NSIS_HOOK_POSTUNINSTALL")).toContain('Delete "$INSTDIR\\${SIEVE_MARKER}"');
  });
});
