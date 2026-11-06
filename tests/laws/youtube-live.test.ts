/**
 * The pure parts of scripts/live/youtube.mjs. The script itself is the user's to
 * run (docs/live/engine-slice-10.md); this holds what it decides from what it sees,
 * and that importing it starts nothing. Its two drivers have never run.
 */
import { describe, expect, it, vi } from "vitest";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { read } from "./files";

const started = vi.hoisted(() => ({ spawn: 0, spawnSync: 0 }));
vi.mock("node:child_process", () => ({
  spawn: () => {
    started.spawn++;
    throw new Error("spawned");
  },
  spawnSync: () => {
    started.spawnSync++;
    throw new Error("spawned");
  },
}));

import * as script from "../../scripts/live/youtube.mjs";

const { SIEVE_ISSUER, VIDEOS_REQUIRED, armLists, hitsDelta, normalProtocol, parseArgs, runVerdict, scriptletPayload, videoVerdict } = script;
const SCRIPT = "scripts/live/youtube.mjs";

const sample = (currentTime: number | null, extra = {}) => ({ currentTime, adShowing: false, enforcement: false, ...extra });
const advancing = [sample(1), sample(5), sample(9)];

const video = (extra = {}) => ({ id: "v", verdict: "pass", reason: "", issuer: SIEVE_ISSUER, protocol: "h2", scriptletPayload: true, ...extra });
const tenPasses = () => Array.from({ length: VIDEOS_REQUIRED }, () => video());

describe("the video site live script", () => {
  it("importing it starts nothing", () => {
    expect(started).toEqual({ spawn: 0, spawnSync: 0 });
  });

  it("the arms are the fixture's rows: the defaults, or the defaults and every gated row", () => {
    const on = ["adguard-base", "adguard-tracking", "adguard-url-tracking", "adguard-dns"];
    expect(armLists(fixture, "adguard")).toEqual(on);
    expect(armLists(fixture, "adguard+ubo")).toEqual([...on, "ubo-filters", "ubo-quick-fixes", "ubo-unbreak"]);
    expect(() => armLists(fixture, "ubo")).toThrow();
  });

  it.each([
    ["advancing and clean", advancing, "pass"],
    ["ad state seen", [sample(1), sample(5, { adShowing: true }), sample(9)], "fail"],
    ["an enforcement message", [sample(1), sample(5, { enforcement: true }), sample(9)], "fail"],
    ["time stuck", [sample(4), sample(4), sample(4)], "fail"],
    ["never played", [sample(0), sample(0)], "unplayed"],
    ["no player", [sample(null), sample(null)], "unplayed"],
    ["no samples", [], "unplayed"],
  ])("a video: %s", (_, samples, verdict) => {
    expect(videoVerdict(samples).verdict).toBe(verdict);
  });

  it("a run passes only with ten played, through the engine, with a scriptlet served", () => {
    expect(runVerdict(tenPasses()).verdict).toBe("pass");
    expect(runVerdict(tenPasses().slice(1)).verdict).toBe("inconclusive");
    const withUnplayed = [...tenPasses().slice(1), video({ verdict: "unplayed", scriptletPayload: false })];
    expect(runVerdict(withUnplayed).verdict).toBe("inconclusive");
  });

  it.each([
    ["the wrong issuer", { issuer: "A Public CA" }],
    ["no issuer known", { issuer: null }],
    ["http/3", { protocol: "h3" }],
    ["no scriptlet payload", { scriptletPayload: false }],
  ])("a run with %s is inconclusive, never pass, and never a fail either", (_, extra) => {
    expect(runVerdict([...tenPasses().slice(1), video(extra)]).verdict).toBe("inconclusive");
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail", ...extra })]).verdict).toBe("inconclusive");
  });

  it("a video or a day-one item that fails fails the run", () => {
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail" })]).verdict).toBe("fail");
    for (const day of [{ homeAds: 1 }, { seek: false }, { quality: false }, { autoplay: false }]) expect(runVerdict(tenPasses(), day).verdict).toBe("fail");
    expect(runVerdict(tenPasses(), { homeAds: 0, seek: true, quality: true, autoplay: true }).verdict).toBe("pass");
  });

  it("parseArgs refuses an unknown browser, arm or flag", () => {
    const good = ["--browser", "chrome", "--arm", "adguard", "--out", "x"];
    expect(parseArgs(good)).toMatchObject({ browser: "chrome", arm: "adguard", out: "x" });
    expect(() => parseArgs(["--browser", "safari", "--arm", "adguard", "--out", "x"])).toThrow(/browser/);
    expect(() => parseArgs(["--browser", "chrome", "--arm", "ubo", "--out", "x"])).toThrow(/arm/);
    expect(() => parseArgs(["--browser", "chrome", "--arm", "adguard"])).toThrow(/out/);
    expect(() => parseArgs([...good, "--nope", "1"])).toThrow(/nope/);
  });

  it("a scriptlet payload is told from the applier alone, in the shape the engine writes", () => {
    const shape = read("engine/crates/sieve-engine/src/inject/payload.rs");
    expect(shape).toContain('String::from("(function(){\\n")');
    expect(shape).toContain("\\nvar sieveApplier=");
    expect(scriptletPayload("(function(){\ntry{flag()}catch(e){}\n})();")).toBe(true);
    expect(scriptletPayload("(function(){\ntry{flag()}catch(e){}\nvar sieveApplier=(function(){})();\n})();")).toBe(true);
    expect(scriptletPayload("(function(){\n\nvar sieveApplier=(function(){})();\n})();")).toBe(false);
    expect(scriptletPayload("window.pageOwn = 1;")).toBe(false);
    expect(scriptletPayload("")).toBe(false);
  });

  it("the issuer is the engine's own", () => {
    expect(read("engine/crates/sieve-engine/src/ca/root.rs")).toContain(SIEVE_ISSUER);
  });

  it("an unreadable status is unknown, never zero", () => {
    expect(hitsDelta(null, { a: 1 })).toBeNull();
    expect(hitsDelta({ a: 1 }, null)).toBeNull();
    expect(hitsDelta({ a: 1 }, { a: 3, b: 2, c: 0 })).toEqual({ a: 2, b: 2 });
    expect(hitsDelta({ a: 3 }, { a: 3 })).toEqual({});
  });

  it("each browser's name for HTTP/3 reads as one", () => {
    for (const name of ["h3", "h3-29", "HTTP/3", "http/3.0"]) expect(normalProtocol(name)).toBe("h3");
    expect(normalProtocol("h2")).toBe("h2");
    expect(normalProtocol(undefined)).toBeNull();
  });

  it("the file holds no engine path but status.json", () => {
    const source = read(SCRIPT);
    const engineFiles = source.match(/"[\w.-]+\.(json|exe|dll|txt)"/g) ?? [];
    expect(engineFiles.filter((f) => !["\"status.json\"", "\"youtube-videos.json\"", "\"filter-lists-v1.json\""].includes(f))).toEqual([]);
    expect(source).toContain('"Sieve", "engine", "status.json"');
    expect(source.match(/"engine"/g)).toHaveLength(1);
  });
});
