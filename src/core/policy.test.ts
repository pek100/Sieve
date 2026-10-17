import { describe, expect, it } from "vitest";
import { APP_STATES, appState, DEFAULT_APP_STATE, effectiveOn, GLOBAL_SWITCH, isAppOn, offKeys, type AppStates } from "./policy";
import { REGISTRY, SETTING_KEYS } from "./settings/registry";

describe("policy (law: effective = global on AND app not off)", () => {
  it("every app is sieved unless the user turned it off", () => {
    expect(DEFAULT_APP_STATE).toBe("sieve");
    expect([...APP_STATES]).toEqual(["sieve", "off"]);
    expect(appState({}, "any")).toBe("sieve");
    expect(isAppOn({}, "any")).toBe(true);
    expect(isAppOn({ any: "off" }, "any")).toBe(false);
    expect(isAppOn({ other: "off" }, "any")).toBe(true);
  });

  it("the truth table: only global on and app on is on", () => {
    for (const global of [true, false]) {
      for (const states of [{}, { a: "off" }] as AppStates[]) {
        expect(effectiveOn(global, states, "a"), `${global} ${JSON.stringify(states)}`).toBe(global && !("a" in states));
      }
    }
  });

  it("the global switch is a registry boolean that defaults on, not a data switch", () => {
    expect(REGISTRY[GLOBAL_SWITCH].kind).toBe("boolean");
    expect(REGISTRY[GLOBAL_SWITCH].default).toBe(true);
  });

  it("there is no Watch level and no per-app filtering switch any more", () => {
    expect(APP_STATES as readonly string[]).not.toContain("watch");
    expect(SETTING_KEYS as readonly string[]).not.toContain("filtering.perApp");
  });

  it("offKeys lists exactly the apps turned off", () => {
    expect([...offKeys({ a: "off", b: "sieve", c: "off" })].sort()).toEqual(["a", "c"]);
    expect(offKeys({}).size).toBe(0);
  });
});
