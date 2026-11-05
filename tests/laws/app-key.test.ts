/**
 * Law: the engine and the app derive an app's key by one rule. The Off list is
 * stored by `appIdentity` keys and matched in the engine by `sieve_ipc::app_key`;
 * the Rust test `app_keys_match_the_shared_fixture` reads this same fixture, so
 * either side changing alone fails.
 */
import { describe, expect, it } from "vitest";
import { appIdentity } from "@/core/apps";
import type { ProcessInfo } from "@/data/protocol";
import fixture from "@/data/fixtures/app-keys-v1.json";

const PID = 1;

describe("app key law", () => {
  it("the fixture covers the identity's every branch", () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(8);
    expect(fixture.cases.some((c) => c.product && c.exe)).toBe(true);
    expect(fixture.cases.some((c) => !c.product && c.exe)).toBe(true);
    expect(fixture.cases.some((c) => !c.product && !c.exe)).toBe(true);
  });

  it.each(fixture.cases)("$why", ({ product, exe, name, key }) => {
    const process: ProcessInfo = { pid: PID, product, exe, name };
    expect(appIdentity(process).key).toBe(key);
  });
});
