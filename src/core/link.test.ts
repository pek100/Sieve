import { describe, expect, it } from "vitest";
import fixture from "@/data/fixtures/engine-ipc-v3.json";
import { EXIT_VIAS, LINK_STATES, parseLinkStatus, type LinkStatus } from "@/data/protocol";
import {
  codeProblem,
  dialAddressProblem,
  EXIT_VIA_TEXT,
  exitReasonWords,
  exitWords,
  hubName,
  isPaired,
  linkHomeLine,
  linkStateLine,
  parsePort,
  shortFingerprint,
  withoutCode,
} from "./link";
import { outcomeWords } from "./log";

const example = (state: LinkStatus["state"]) => parseLinkStatus(fixture.linkStatuses.find((s) => s.state === state))!;
const NOW = 1_793_000_090_000;

describe("the link's state in words", () => {
  it("every state has a line, and none of them claims the hub when routes are down", () => {
    for (const state of LINK_STATES) {
      const line = linkStateLine({ ...example(state === "unknown" ? "off" : state), state }, true, NOW);
      expect(line.text, state).toMatch(/^[A-Z]/);
      expect(line.text, state).not.toMatch(/undefined|null/);
    }
    expect(linkStateLine(example("up"), true, NOW)).toMatchObject({ tone: "working" });
    expect(linkStateLine(example("up"), true, NOW).text).toMatch(/^Exiting through home since [^.]+\. Sites see its address, not this computer's\. Listening for home on 198\.51\.100\.30:7443\.$/);
    expect(linkStateLine(example("connecting"), false, NOW).text).toMatch(/starts when Sieve routes traffic; until then this computer's network works as usual/);
  });

  it("down says what the hub-down setting does, and the engine's last error", () => {
    const down = example("down");
    expect(linkStateLine(down, true, NOW)).toEqual({
      tone: "warning",
      text: expect.stringMatching(/^Home cannot be reached since .*, so sieved apps' new connections are stopped rather than leaving from this computer's own address\. The last error: dial 203\.0\.113\.20:7443: timed out: connect\.$/),
    });
    const direct = { ...down, settings: { ...down.settings!, on_hub_down: "direct" as const } };
    expect(linkStateLine(direct, true, NOW).text).toMatch(/so sieved apps leave directly from this computer, from its own address/);
  });

  it("unpaired with an error says the pairing did not work; a nameless hub is plain words", () => {
    expect(linkStateLine({ state: "unpaired", last_error: "the code has expired" }, true, NOW)).toEqual({ tone: "warning", text: "Not paired. The last pairing did not work: the code has expired." });
    expect(hubName({})).toBe("the other device");
    expect(linkStateLine({ ...example("down"), hub_name: undefined }, true, NOW).text).toMatch(/^The other device cannot be reached/);
  });

  it("paired means a record with choices, not a pairing in progress", () => {
    expect(isPaired(example("off"))).toBe(true);
    expect(isPaired(example("pairing"))).toBe(false);
    expect(isPaired(example("unpaired"))).toBe(false);
    expect(isPaired(undefined)).toBe(false);
  });
});

describe("Home's line", () => {
  it("only while exit is on and Sieve routes: short while up, a notice while it cannot be reached", () => {
    expect(linkHomeLine(undefined, true), "an older engine").toBeNull();
    expect(linkHomeLine(example("off"), true), "exit off").toBeNull();
    expect(linkHomeLine(example("up"), false), "Sieve not routing: the normal network").toBeNull();
    expect(linkHomeLine(example("up"), true)).toEqual({ tone: "neutral", text: "Exiting through home: sites see its address, not this computer's." });
    expect(linkHomeLine(example("down"), true)).toEqual({ tone: "warning", text: "Home cannot be reached, so sieved apps' new connections are stopped rather than leaving from this computer's own address." });
    expect(linkHomeLine(example("connecting"), true)?.text).toBe("Connecting to home. Until it answers, sieved apps leave directly from this computer, from its own address.");
  });
});

describe("what the owner types", () => {
  it("a code is judged by size only, and a problem never says it back", () => {
    expect(codeProblem("SL1-abc")).toBeNull();
    expect(codeProblem("   ")).toMatch(/Paste the pairing code/);
    const long = `SL1-${"x".repeat(600)}`;
    expect(codeProblem(long)).not.toContain(long);
    expect(codeProblem(long)).toMatch(/too long/);
  });

  it("a code an engine says back is taken out of the words", () => {
    expect(withoutCode("bad SL1-abc here", " SL1-abc\n")).toBe("bad (the pairing code) here");
    expect(withoutCode("nothing", "")).toBe("nothing");
  });

  it("an address has its port; empty only when the code carries one", () => {
    expect(dialAddressProblem("203.0.113.20:7443", false)).toBeNull();
    expect(dialAddressProblem("[2001:db8::1]:7443", false)).toBeNull();
    expect(dialAddressProblem("", true)).toBeNull();
    expect(dialAddressProblem("", false)).toMatch(/address and port/);
    expect(dialAddressProblem("203.0.113.20", false)).toMatch(/with its port/);
    expect(dialAddressProblem("203.0.113.20:70000", false)).toMatch(/1 to 65535/);
    expect([parsePort("7443"), parsePort("0"), parsePort("65536"), parsePort("74x")]).toEqual([7443, null, null, null]);
  });

  it("a fingerprint is shortened for the line, whole elsewhere", () => {
    expect(shortFingerprint("5e1a9c0d4b7f2e8a6c3d1f0b9e7a5c3d2b1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d")).toBe("5e1a9c0d...0a9f8e7d");
  });
});

describe("the log's exit rows", () => {
  it("every way out has words; a refusal carries the other device's own reason and never blames the app or Sieve", () => {
    for (const via of EXIT_VIAS) expect(EXIT_VIA_TEXT[via], via).toMatch(/^[A-Z]/);
    expect(exitWords("refused", "denied: shop.example is not on this device's allow-list")).toBe("The other device refused it: denied: shop.example is not on this device's allow-list");
    expect(exitWords("refused")).toBe("The other device refused it");
    expect(exitWords("hub", "ignored")).toBe("Left through the other device");
    for (const o of fixture.outcomes.filter((x) => x.kind === "exit")) {
      const words = outcomeWords(o as never);
      expect(words, JSON.stringify(o)).not.toMatch(/^Unknown$|Sieve blocked|the app/);
    }
    expect(outcomeWords({ kind: "exit", via: "unknown" })).toBe("Went out in a way this version of Sieve cannot name");
    expect(exitReasonWords("udp")).toMatch(/^UDP/);
    expect(exitReasonWords("the hub is not reachable")).toBe("the hub is not reachable");
  });
});
