// Source-only preservation audit. This does not compile Rust or run an engine.
// Supply the pre-experiment revision explicitly so the comparison stays useful
// after the implementation is committed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const base = process.argv[2];
assert(base, "usage: node scripts/check-relay-experiments.mjs <baseline-revision>");
const read = (path) => readFileSync(path, "utf8").replace(/\r\n/g, "\n");
const before = (path) => execFileSync("git", ["show", `${base}:${path}`], { encoding: "utf8" }).replace(/\r\n/g, "\n");
const engine = "engine/crates/sieve-engine/src/";
const block = (text, start, end) => {
  const from = text.indexOf(start);
  assert(from >= 0, start);
  const to = text.indexOf(end, from);
  assert(to >= 0, end);
  return text.slice(from, to).trim();
};
const relay = engine + "flow/relay.rs";
assert.equal(
  block(read(relay), "pub async fn relay_tcp<", "/// Diagnostic counterpart"),
  block(before(relay), "pub async fn relay_tcp<", "#[cfg(test)]"),
);
console.log("PASS: original relay_tcp source unchanged");

const device = engine + "tun/device.rs";
const readerStart = "        let (tx, rx) = mpsc::channel(QUEUE);";
assert.equal(block(read(device), readerStart, "        Self {"), block(before(device), readerStart, "        Self {"));
console.log("PASS: original TUN reader loop unchanged");

const profile = (text) => text.match(/\[profile\.release\]\n([\s\S]*?)(?=\n\[|$)/)?.[1].split("\n#")[0].trim();
assert.equal(profile(read("engine/Cargo.toml")), profile(before("engine/Cargo.toml")));
console.log("PASS: release profile unchanged");

for (const path of [engine + "flow/flows.rs", ...execFileSync("git", ["ls-files", engine + "dns"], { encoding: "utf8" }).trim().split(/\r?\n/).filter(Boolean)]) {
  assert.equal(read(path), before(path), path);
}
console.log("PASS: attribution and DNS sources unchanged");

const stack = read("engine/vendor/ipstack/src/lib.rs");
assert(stack.includes("let mut buffer = vec![0_u8; config.mtu as usize + offset];"));
assert(read(engine + "stack/relay.rs").includes("const DATAGRAM: usize = 65_535;"));
assert(read(device).includes("adapter.start_session(RING_BYTES)"));
console.log("PASS: ipstack packet buffer follows MTU; existing datagram and ring sizing retained");
