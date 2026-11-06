/**
 * Law 14, the settings password and the first-run guide. The hash stays in Rust
 * and off the wire; every UI write passes the one gate, except the guide's one
 * flag, which is the only setting it writes.
 */
import { describe, expect, it } from "vitest";
import { MIN_PASSWORD_CHARS } from "@/core/lock";
import { SETTING_KEYS } from "@/core/settings/registry";
import { WELCOME_DONE } from "@/core/welcome";
import { parseLockStatus, parseLockVerdict } from "@/data/protocol";
import { hits, read, walk } from "./files";

const nonTest = (f: string) => !/\.test\.tsx?$/.test(f);
const code = (dir: string) => walk(dir, [".ts", ".tsx"]).filter(nonTest);

describe("settings password law", () => {
  it("the minimum length agrees between TS and Rust", () => {
    const rust = read("src-tauri/src/lock.rs").match(/pub const MIN_PASSWORD_CHARS: usize = (\d+);/);
    expect(Number(rust?.[1])).toBe(MIN_PASSWORD_CHARS);
  });

  it("no file in src other than the mock names a stored password field", () => {
    const files = code("src").filter((f) => f !== "src/data/lock-mock.ts");
    expect(files.flatMap((f) => hits(f, /\bphc\b|password_?hash|passwordStored|storedPassword|argon/i))).toEqual([]);
  });

  it("lock_status and lock_verify answers have no hash field, in Rust and through the parsers", () => {
    const rust = read("src-tauri/src/lock.rs");
    for (const name of ["LockStatus", "LockVerdict"]) {
      const body = rust.match(new RegExp(`pub struct ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1];
      expect(body, name).toBeDefined();
      expect(body, name).not.toMatch(/phc|hash/);
    }
    const leak = { state: "set", ok: true, retry_after_secs: 0, phc: "$argon2id$x" };
    expect(Object.keys(parseLockStatus(leak)).sort()).toEqual(["retry_after_secs", "state"]);
    expect(Object.keys(parseLockVerdict(leak)).sort()).toEqual(["ok", "retry_after_secs"]);
  });

  it("anything unknown reads shut: status unreadable, verdict no", () => {
    for (const bad of [null, undefined, 3, {}, { state: "open" }]) expect(parseLockStatus(bad).state, JSON.stringify(bad)).toBe("unreadable");
    for (const bad of [null, {}, { ok: "true" }, { ok: 1 }]) expect(parseLockVerdict(bad).ok, JSON.stringify(bad)).toBe(false);
  });

  it("the password is not a settings key, so export, import and reset cannot reach it", () => {
    expect(SETTING_KEYS.filter((k) => k.startsWith("password."))).toEqual(["password.idleMinutes"]);
  });

  it("no component writes settings directly, except the settings view and the log's row actions, which go through guard", () => {
    const writers = code("src/components").filter((f) => hits(f, /\bsettings\.(set|reset|replace)\(/).length > 0);
    expect(writers).toEqual(["src/components/sieve/log/use-log.ts", "src/components/sieve/settings/use-settings-view.ts"]);
    for (const writer of writers) {
      const view = read(writer);
      // Every write in it sits inside a guard call.
      expect(view.match(/guard\(/g)?.length, writer).toBeGreaterThanOrEqual(view.match(/settings\.(set|reset|replace)\(/g)?.length ?? 0);
    }
  });

  it("the hooks every other component writes through are gated", () => {
    const hooks = read("src/hooks/use-sieve.ts");
    expect(hooks).toMatch(/lockController\.guard\(\(\) => settings\.set\(key, v\)\.then\(\(\) => true\)\)/);
    expect(hooks).toMatch(/lockController\.guard\(\(\) => engineController\.stopAdguard\(\)\)/);
    expect(hooks).toMatch(/lockController\.guard\(\(\) => engineController\.startAdguard\(\)\)/);
    // No hook other than the gate's own writes settings.
    expect(code("src/hooks").filter((f) => f !== "src/hooks/runtime.ts").flatMap((f) => hits(f, /\bsettings\.(reset|replace)\(/))).toEqual([]);
  });
});

describe("first-run guide law", () => {
  const guide = [...code("src/components/sieve/welcome"), "src/core/welcome.ts", "src/hooks/use-welcome.ts"];

  it("it never writes a setting other than its own flag, and that write is its only way past the gate", () => {
    expect(WELCOME_DONE).toBe("startup.welcomeDone");
    // Skip is always one click, so this one write does not wait on a password.
    // It changes no traffic and no protected setting, and it can only say "done".
    const writes = guide.flatMap((f) => hits(f, /\bsettings\.(set|reset|replace)\(/));
    expect(writes).toHaveLength(1);
    expect(writes[0]).toContain("src/hooks/use-welcome.ts");
    expect(writes[0]).toContain("settings.set(WELCOME_DONE, true)");
    const reads = guide.flatMap((f) => [...read(f).matchAll(/useSetting\(([^)]*)\)/g)].map((m) => m[1]));
    expect(reads).toEqual(["WELCOME_DONE"]);
    expect(read("src/hooks/use-welcome.ts")).toMatch(/const \[finished\] = useSetting\(WELCOME_DONE\)/);
    const view = guide.flatMap((f) => hits(f, /useSettingsView\(/));
    for (const line of view) expect(line).toMatch(/const \{ doc, lockOf \} = useSettingsView\(/);
  });

  it("it never names the engine's policy", () => {
    expect(guide.flatMap((f) => hits(f, /setPolicy|set_policy|ENGINE_SWITCH|filtering\.engine/))).toEqual([]);
  });
});
