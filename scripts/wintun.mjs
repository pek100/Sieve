// Puts Wintun 0.14.1's wintun.dll and its licence beside the release engine
// (engine/target/release), where the NSIS hook embeds them. The DLL is never
// in the repo: it comes from SIEVE_WINTUN_DLL or the machine's copy at
// E:\ml-tools\wintun (docs/research/2026-10-17-wintun-spike.md, section 3).
// Its SHA-256 must equal the pin the engine checks before loading it
// (WINTUN_SHA256 in engine/crates/sieve-engine/src/tun/mod.rs, read from
// there so there is one pin); any other file fails the build.
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tun = readFileSync(join(root, "engine/crates/sieve-engine/src/tun/mod.rs"), "utf8");
const pin = tun.match(/pub const WINTUN_SHA256: &str = "([0-9a-f]{64})";/)?.[1];
const licenceName = tun.match(/pub const WINTUN_LICENSE: &str = "([^"]+)";/)?.[1];
if (!pin || !licenceName) throw new Error("wintun.mjs: WINTUN_SHA256 or WINTUN_LICENSE not found in tun/mod.rs");

const source = process.env.SIEVE_WINTUN_DLL ?? "E:\\ml-tools\\wintun\\wintun\\bin\\amd64\\wintun.dll";
if (!existsSync(source)) throw new Error(`wintun.mjs: ${source} not found (set SIEVE_WINTUN_DLL to Wintun 0.14.1's bin/amd64/wintun.dll)`);
const hash = createHash("sha256").update(readFileSync(source)).digest("hex");
if (hash !== pin) throw new Error(`wintun.mjs: ${source} has SHA-256 ${hash}, not the pinned ${pin}`);

const out = join(root, "engine/target/release");
copyFileSync(source, join(out, "wintun.dll"));
copyFileSync(join(root, "engine/vendor/wintun/LICENSE.txt"), join(out, licenceName));
console.log(`wintun.mjs: wintun.dll (${hash}) and ${licenceName} copied to ${out}`);
