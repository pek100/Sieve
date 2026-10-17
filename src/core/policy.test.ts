import { describe, expect, it } from "vitest";
import { ceiling, DEFAULT_LEVEL, effectiveLevel, LEVEL_REQUIRES, LEVELS, lockedReason, requestedLevel } from "./policy";

const on = (keys: string[]) => (k: string) => keys.includes(k);

describe("policy (law: effective = min(requested, ceiling))", () => {
  it("the ceiling is watch until DNS filtering is on AND its live check passed", () => {
    expect(ceiling(on([]), on([]))).toBe("watch");
    expect(ceiling(on(["filtering.dns"]), on([]))).toBe("watch");
    expect(ceiling(on([]), on(["filtering.dns"]))).toBe("watch");
    expect(ceiling(on(["filtering.dns"]), on(["filtering.dns"]))).toBe("sieve");
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
      const reason = lockedReason(level, "off", switchOn, label);
      if (needs === undefined || level === "off") expect(reason, level).toBeNull();
      else expect(reason, level).toBe(`Needs label of ${needs}, which is off`);
    }
    expect(new Set(asked)).toEqual(new Set(Object.values(LEVEL_REQUIRES)));
    // On but not proven: the reason names the live check, still from the same switch.
    expect(lockedReason("sieve", "watch", () => true, label)).toBe(`Needs label of ${LEVEL_REQUIRES.sieve} to pass its live check`);
    // Reachable levels have no reason.
    expect(lockedReason("sieve", "sieve", () => false, label)).toBeNull();
  });

  it("apps not listed use the default level", () => {
    expect(requestedLevel({}, "any")).toBe(DEFAULT_LEVEL);
    expect(requestedLevel({ any: "off" }, "any")).toBe("off");
  });
});
