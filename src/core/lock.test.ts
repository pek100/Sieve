import { describe, expect, it } from "vitest";
import { LOCK_PHASES, MIN_PASSWORD_CHARS, canWrite, hasPassword, isShut, passwordProblem } from "./lock";

describe("lock phases", () => {
  it("a write runs now only with no password or after it was given", () => {
    expect(LOCK_PHASES.filter(canWrite)).toEqual(["none", "unlocked"]);
  });

  it("rows close when locked or unreadable, never while checking", () => {
    expect(LOCK_PHASES.filter(isShut)).toEqual(["locked", "unreadable"]);
    expect(LOCK_PHASES.filter(hasPassword)).toEqual(["locked", "unlocked"]);
  });
});

describe("passwordProblem", () => {
  it("says what is wrong, short first", () => {
    const ok = "x".repeat(MIN_PASSWORD_CHARS);
    expect(passwordProblem("short", "short")).toContain(`${MIN_PASSWORD_CHARS} characters`);
    expect(passwordProblem(ok, `${ok}y`)).toContain("not the same");
    expect(passwordProblem(ok, ok)).toBeNull();
  });
});
