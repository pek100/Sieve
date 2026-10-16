import { describe, expect, it } from "vitest";
import { ceiling, DEFAULT_LEVEL, effectiveLevel, requestedLevel } from "./policy";

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

  it("apps not listed use the default level", () => {
    expect(requestedLevel({}, "any")).toBe(DEFAULT_LEVEL);
    expect(requestedLevel({ any: "off" }, "any")).toBe("off");
  });
});
