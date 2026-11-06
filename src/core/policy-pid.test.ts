import { describe, expect, it } from "vitest";
import { offAll, offAllNotice, setAppState } from "./apps-actions";
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

  it("bulk Off's notice promises every app only when every listed app took it", () => {
    expect(offAllNotice(["firefox", "vm:ubuntu"])).toBe("Every app is off");
    expect(offAllNotice(["pid 77", "firefox"])).toBe("Every app that can be turned off is off. 1 stays sieved: Windows gives it no name.");
    expect(offAllNotice(["pid 77", "pid 78", "firefox"])).toBe("Every app that can be turned off is off. 2 stay sieved: Windows gives them no name.");
  });

  it("only that exact form: a name with a number keeps its Off", () => {
    expect(canTurnOff("pid 77")).toBe(false);
    for (const key of ["pid", "pid 77 helper", "rapid 77", "vm:ubuntu"]) expect(canTurnOff(key), key).toBe(true);
  });
});
