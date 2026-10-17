import { describe, expect, it } from "vitest";
import { ceiling, DEFAULT_LEVEL, effectiveLevel, LEVEL_REQUIRES, LEVELS, lockedReason, requestedLevel } from "./policy";
import { REGISTRY, unavailableReason } from "./settings/registry";
import { DNS_SWITCH } from "./dns";

const on = (keys: string[]) => (k: string) => keys.includes(k);
const SIEVE_NEEDS = LEVEL_REQUIRES.sieve!;
const never = () => null;

describe("policy (law: effective = min(requested, ceiling))", () => {
  it("the ceiling is watch until the switch sieve needs is on AND its live check passed", () => {
    expect(ceiling(on([]), on([]))).toBe("watch");
    expect(ceiling(on([SIEVE_NEEDS]), on([]))).toBe("watch");
    expect(ceiling(on([]), on([SIEVE_NEEDS]))).toBe("watch");
    expect(ceiling(on([SIEVE_NEEDS]), on([SIEVE_NEEDS]))).toBe("sieve");
  });

  it("honesty: DNS filtering never unlocks the per-app sieve level (DNS cannot tell apps apart)", () => {
    expect(SIEVE_NEEDS).toBe("filtering.perApp");
    expect(SIEVE_NEEDS).not.toBe(DNS_SWITCH);
    expect(ceiling(on([DNS_SWITCH]), on([DNS_SWITCH]))).toBe("watch");
    // Per-app filtering is declared unavailable in this build, with the reason.
    expect(REGISTRY["filtering.perApp"].unavailable).toMatch(/network driver/);
    expect(unavailableReason(SIEVE_NEEDS)).toMatch(/network driver/);
    expect(unavailableReason(DNS_SWITCH)).toBeNull();
  });

  it("a requested sieve is clamped to watch while the ceiling is watch", () => {
    expect(effectiveLevel("sieve", "watch")).toBe("watch");
    expect(effectiveLevel("off", "sieve")).toBe("off");
    expect(effectiveLevel("sieve", "sieve")).toBe("sieve");
  });

  it("lockedReason reads the switch LEVEL_REQUIRES names, whatever its key", () => {
    const asked: string[] = [];
    const switchOn = (k: string) => (asked.push(k), false);
    const label = (k: string) => `label of ${k}`;
    for (const level of LEVELS) {
      const needs = LEVEL_REQUIRES[level];
      const reason = lockedReason(level, "off", switchOn, label, never);
      if (needs === undefined || level === "off") expect(reason, level).toBeNull();
      else expect(reason, level).toBe(`Needs label of ${needs}, which is off`);
    }
    expect(new Set(asked)).toEqual(new Set(Object.values(LEVEL_REQUIRES)));
    // On but not proven: the reason names the live check, still from the same switch.
    expect(lockedReason("sieve", "watch", () => true, label, never)).toBe(`Needs label of ${SIEVE_NEEDS} to pass its live check`);
    // Reachable levels have no reason.
    expect(lockedReason("sieve", "sieve", () => false, label, never)).toBeNull();
  });

  it("an unavailable switch is said with its reason, derived from the registry", () => {
    const label = (k: string) => `label of ${k}`;
    expect(lockedReason("sieve", "watch", () => false, label, unavailableReason)).toBe(
      `Needs label of ${SIEVE_NEEDS}. ${REGISTRY["filtering.perApp"].unavailable}`,
    );
  });

  it("apps not listed use the default level", () => {
    expect(requestedLevel({}, "any")).toBe(DEFAULT_LEVEL);
    expect(requestedLevel({ any: "off" }, "any")).toBe("off");
  });
});
