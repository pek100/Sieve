/**
 * Law: the app and the engine read one upstream grammar (plan 1.4, contract C3).
 * `src/data/fixtures/upstream-grammar.json` is the table. This file feeds it to
 * `parseUpstream`; `engine/crates/sieve-engine/tests/upstream_grammar.rs` feeds
 * the same file to the engine's `Upstream`. A form on which they disagreed would
 * be deleted by the migration or refused by an import while the engine could use
 * it, or the other way round.
 */
import { describe, expect, it } from "vitest";
import { parseUpstream } from "@/core/upstream";
import { settingDef } from "@/core/settings/registry";
import ipc from "@/data/fixtures/engine-ipc-v3.json";
import table from "@/data/fixtures/upstream-grammar.json";
import { read } from "./files";

describe("law: one upstream grammar", () => {
  it.each(table.accept)("accepts %j", (raw) => {
    expect(parseUpstream(raw)).not.toBeNull();
  });

  it.each(table.refuse)("refuses %j", (raw) => {
    expect(parseUpstream(raw)).toBeNull();
  });

  it("the table names one answer per form and covers every kind", () => {
    expect(table.accept.filter((raw) => table.refuse.includes(raw))).toEqual([]);
    for (const kind of ["doh", "dot", "doq"]) expect(table.accept.some((raw) => parseUpstream(raw)?.kind === kind), kind).toBe(true);
  });

  it("the app's default list is in the table", () => {
    for (const raw of settingDef("filtering.upstreams").default as readonly string[]) expect(table.accept).toContain(raw);
  });

  it("the app's default list is the engine's, so a new install sends nothing and claims nothing false", () => {
    const held = ipc.engine.find((m) => m.type === "dns_upstreams") as unknown as { revision: number; upstreams: string[] };
    expect(settingDef("filtering.upstreams").default).toEqual(held.upstreams);
    expect(held.revision).toBe(0);
    expect(read("engine/crates/sieve-engine/src/dns/config.rs")).toContain("engine-ipc-v3.json");
  });

  it("the engine's half reads this same table and asks its real parser", () => {
    const rust = read("engine/crates/sieve-engine/tests/upstream_grammar.rs");
    expect(rust).toContain('include_str!("../../../../src/data/fixtures/upstream-grammar.json")');
    expect(rust).toContain("sieve_engine::dns::upstream::Upstream");
  });
});
