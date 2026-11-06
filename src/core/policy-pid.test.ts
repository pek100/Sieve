import { describe, expect, it } from "vitest";
import { offAll, setAppState } from "./apps-actions";
import { appState, canTurnOff, isAppOn, offKeys } from "./policy";

describe("a row named only by its pid has no Off", () => {
  it("a stored Off on it reads as on and is never sent to the engine", () => {
    const stored = { "pid 77": "off", firefox: "off" } as const;
    expect(appState(stored, "pid 77")).toBe("sieve");
    expect(isAppOn(stored, "pid 77")).toBe(true);
    expect([...offKeys(stored)]).toEqual(["firefox"]);
  });

  it("turning it off stores nothing and clears an old value", () => {
    expect(setAppState({}, "pid 77", "off")).toEqual({});
    expect(setAppState({ "pid 77": "off" }, "pid 77", "off")).toEqual({});
    expect(offAll({}, ["pid 77", "firefox"])).toEqual({ firefox: "off" });
  });

  it("only that exact form: a name with a number keeps its Off", () => {
    expect(canTurnOff("pid 77")).toBe(false);
    for (const key of ["pid", "pid 77 helper", "rapid 77", "vm:ubuntu"]) expect(canTurnOff(key), key).toBe(true);
  });
});
