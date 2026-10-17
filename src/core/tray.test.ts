import { describe, expect, it } from "vitest";
import { parseTrayAction, trayState } from "./tray";

const fmt = () => "14:05";

describe("tray state (derived from the phase)", () => {
  it("live can pause, paused can resume and says until when, anything not live is dimmed", () => {
    expect(trayState("live", null, fmt)).toEqual({ tooltip: "Sieve: live", canPause: true, canResume: false, dim: false });
    expect(trayState("paused", 1, fmt)).toEqual({ tooltip: "Sieve: paused until 14:05", canPause: false, canResume: true, dim: true });
    expect(trayState("off", null, fmt)).toMatchObject({ canPause: false, canResume: false, dim: true, tooltip: "Sieve: off" });
    expect(trayState("error", null, fmt)).toMatchObject({ tooltip: "Sieve: no data", canPause: true });
  });

  it("accepts only the actions Rust sends", () => {
    expect(parseTrayAction({ kind: "pause", minutes: 5 })).toEqual({ kind: "pause", minutes: 5 });
    expect(parseTrayAction({ kind: "resume" })).toEqual({ kind: "resume" });
    expect(parseTrayAction({ kind: "pause", minutes: -1 })).toBeNull();
    expect(parseTrayAction({ kind: "quit" })).toBeNull();
    expect(parseTrayAction("pause")).toBeNull();
    expect(parseTrayAction(null)).toBeNull();
  });
});
