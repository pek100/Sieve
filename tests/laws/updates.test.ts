/**
 * Law 13, signed updates (plan 7.5): the private key never enters the repo, the
 * app can only ask, the engine alone fetches, verifies and replaces, and only
 * one file in the engine's product code starts a process.
 *
 * The walk reads `git ls-files --cached --others --exclude-standard`: tracked
 * and untracked, ignored excluded. Every secret-key pattern is built at run
 * time, so this file does not match itself, and proven on a key built at run
 * time, so a pattern that went dead fails here.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import ipc from "@/data/fixtures/engine-ipc-v2.json";
import { ROOT, read, walk } from "./files";

/** A minisign secret key's box line, unencrypted and encrypted (read off a real key, 2026-11-05). */
const BOX_PREFIXES = ["RWQAAEIy", "RWRTY0Iy"];
const MIN_BOX_BASE64 = 100;
/** The header line of a secret key file; the first line is free text, so this alone is not enough. */
const HEADERS = ["minisign encrypted secret key", "minisign secret key", "rsign encrypted secret key"];
const MAX_SCAN_BYTES = 32 * 1024 * 1024;
/** The repo has far more files than this: an empty or broken walk fails. */
const MIN_FILES = 300;

const b64 = (text: string) => Buffer.from(text, "latin1").toString("base64");

/** Every secret-key witness: the box line, the header, and both inside Tauri's base64 wrapper. */
const PATTERNS: readonly RegExp[] = [
  ...BOX_PREFIXES.map((p) => new RegExp(`${p}[A-Za-z0-9+/=]{${MIN_BOX_BASE64},}`)),
  ...HEADERS.map((h) => new RegExp(`untrusted comment: ${h}`, "i")),
  // A base64 wrapper shifts by the text's offset, so each of the three alignments is checked.
  ...HEADERS.flatMap((h) => [0, 1, 2].map((shift) => new RegExp(b64("x".repeat(shift) + `untrusted comment: ${h}`).slice(shift === 0 ? 0 : 4, -4).replace(/[+/]/g, "\\$&")))),
];

function secretIn(bytes: Buffer): RegExp | undefined {
  const text = bytes.toString("latin1");
  return PATTERNS.find((p) => p.test(text));
}

const repoFiles = () =>
  execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 28 })
    .split("\0")
    .filter(Boolean);

/** Product source: everything before the file's first test module. */
const product = (rel: string) => read(rel).split("#[cfg(test)]")[0];

describe("updates law", () => {
  describe("no secret key in the repo", () => {
    it("control: each pattern catches a key built at run time", () => {
      const body = "A".repeat(MIN_BOX_BASE64 + 40);
      for (const prefix of BOX_PREFIXES) {
        const key = `untrusted comment: test\n${prefix}${body}\n`;
        expect(secretIn(Buffer.from(key)), prefix).toBeDefined();
      }
      for (const header of HEADERS) {
        const key = `untrusted comment: ${header}\nAAAA\n`;
        expect(secretIn(Buffer.from(key)), header).toBeDefined();
        for (const lead of ["", "x", "xy"]) {
          expect(secretIn(Buffer.from(b64(lead + key))), `wrapped after ${JSON.stringify(lead)}: ${header}`).toBeDefined();
        }
      }
      // A public key and an ordinary signature are no secret key.
      expect(secretIn(Buffer.from("untrusted comment: minisign public key 1234\nRWQxyz\n"))).toBeUndefined();
      expect(secretIn(Buffer.from(`RWQAAEIy${"A".repeat(MIN_BOX_BASE64 - 1)}`))).toBeUndefined();
    });

    it("no tracked or untracked file holds one, or is named like one", () => {
      const files = repoFiles();
      expect(files.length).toBeGreaterThan(MIN_FILES);
      expect(files.filter((f) => f.endsWith(".key"))).toEqual([]);
      const found: string[] = [];
      let scanned = 0;
      for (const rel of files) {
        const abs = join(ROOT, rel);
        let size: number;
        try {
          size = statSync(abs).size;
        } catch {
          continue; // Deleted in the working tree: nothing to read.
        }
        if (size > MAX_SCAN_BYTES) continue;
        scanned++;
        const hit = secretIn(readFileSync(abs));
        if (hit) found.push(`${rel}: ${hit.source}`);
      }
      expect(scanned).toBeGreaterThan(MIN_FILES);
      expect(found).toEqual([]);
    });

    it("the compiled-in key is a public key or the marked placeholder", () => {
      const trust = read("engine/crates/sieve-engine/src/update/trust.rs");
      const key = trust.match(/pub const PUBLIC_KEY: &str = "([^"]*)";/)?.[1] ?? "";
      expect(key.startsWith("PLACEHOLDER") || /^RW[A-Za-z0-9+/]{54}$/.test(key), key).toBe(true);
      expect(trust).toContain('pub const UPDATE_BASE_URL: &str = "https://');
    });
  });

  describe("the app only asks", () => {
    it("request_update is the only client message naming an update, and it carries only its type", () => {
      const named = ipc.client.filter((m) => /update|install|release/i.test(m.type));
      expect(named).toEqual([{ type: "request_update" }]);
      const crate = read("engine/crates/sieve-ipc/src/lib.rs");
      const client = crate.match(/pub enum ClientMessage \{([\s\S]*?)\n\}/)?.[1] ?? "";
      expect(client).toMatch(/^\s*RequestUpdate \{\},$/m);
    });

    it("no client message carries a path, a URL, a file or data", () => {
      expect(ipc.client.length).toBeGreaterThan(1);
      const fields = ipc.client.flatMap((m) => Object.keys(m));
      expect(fields.filter((f) => /path|url|file|data|bytes|version$/i.test(f) && f !== "app_version")).toEqual([]);
    });

    it("the app's command takes no argument", () => {
      const engine = read("src-tauri/src/engine.rs");
      expect(engine).toContain("pub async fn engine_request_update() -> Result<EngineStatus, String>");
      expect(read("src/data/engine-source.ts")).toContain('invoke<unknown>("engine_request_update"))');
    });

    it("Tauri's updater plugin is used nowhere", () => {
      for (const manifest of ["src-tauri/Cargo.toml", "package.json"]) {
        expect(read(manifest), manifest).not.toMatch(/plugin-updater/);
      }
    });
  });

  describe("the engine alone replaces files", () => {
    const CRATES = "engine/crates";
    const BINS = /\/src\/bin\/|\/examples\/|\/tests\//;
    const PROCESS = /\bCommand::new\b|\bCreateProcess/;
    const sources = () => walk(CRATES, [".rs"]).filter((f) => !BINS.test(f));

    it("control: the scan reads the engine, and sees the one allowed file", () => {
      expect(sources().length).toBeGreaterThan(20);
      expect(PROCESS.test(product("engine/crates/sieve-engine/src/update/win.rs"))).toBe(true);
    });

    it("only update/win.rs starts a process in product code", () => {
      const starters = sources().filter((f) => PROCESS.test(product(f)));
      expect(starters).toEqual(["engine/crates/sieve-engine/src/update/win.rs"]);
    });

    it("swap takes no path from the index, and every name it joins is validated first", () => {
      const swap = product("engine/crates/sieve-engine/src/update/swap.rs");
      expect(swap).not.toMatch(/\bIndex\b|\bEntry\b/);
      const index = read("engine/crates/sieve-engine/src/update/index.rs");
      expect(index.indexOf("valid_file_name(&entry.file)")).toBeGreaterThan(-1);
      const cycle = product("engine/crates/sieve-engine/src/update/cycle.rs");
      // Writes under `update/` start from the engine folder or the exe's folder; the
      // only name from the index that joins them is the validated bare `entry.file`.
      const joined = [...cycle.matchAll(/\.join\(([^)]*)\)/g)].map((m) => m[1]);
      for (const arg of joined) expect(arg, arg).toMatch(/^&?(entry\.file|name|DATA_DIR|DATA_STAGING_DIR|STAGING_DIR|INDEX_FILE)$/);
      expect(cycle).toContain("self.engine_dir");
      expect(cycle).toContain("self.install_dir");
    });

    it("update/ opens a socket only through the pin", () => {
      const https = product("engine/crates/sieve-engine/src/update/https.rs");
      expect(https).toContain("pin::pinned_socket(");
      expect(https).not.toMatch(/TcpStream::connect|std::net::TcpStream/);
    });
  });
});
