/**
 * What scripts/live/youtube.mjs decides from what it sees, that importing it starts
 * nothing, and that a browser dies whatever goes wrong. The script itself is the
 * user's to run (docs/live/engine-slice-10.md): its drivers meet a fake socket here
 * and have never met a browser.
 */
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "@/data/fixtures/filter-lists-v1.json";
import { read } from "./files";

const started = vi.hoisted(() => ({ spawn: 0, spawnSync: [] as string[][], child: null as unknown }));
vi.mock("node:child_process", () => ({
  spawn: () => {
    started.spawn++;
    if (!started.child) throw new Error("spawned");
    return started.child;
  },
  spawnSync: (_: string, args: string[]) => {
    started.spawnSync.push(args);
    if (!started.child) throw new Error("spawned");
    return { status: 0 };
  },
}));

import * as script from "../../scripts/live/youtube.mjs";

const startedAtImport = { spawn: started.spawn, spawnSync: started.spawnSync.length };

const { BidiDriver, CdpDriver, SIEVE_ISSUER, STATUS_SETTLE_MS, VIDEOS_REQUIRED, armLists, heldLists, hitsDelta, normalProtocol, parseArgs, runVerdict, scriptletDocuments, videoVerdict, withBrowser } = script;
const SCRIPT = "scripts/live/youtube.mjs";

const sample = (currentTime: number | null, extra = {}) => ({ currentTime, adShowing: false, enforcement: false, ...extra });
const times = (...at: number[]) => at.map((t) => sample(t));
const advancing = times(1, 5, 9);

const video = (extra = {}) => ({ id: "v", verdict: "pass", reason: "", issuer: SIEVE_ISSUER, protocol: "h2", ...extra });
const tenPasses = () => Array.from({ length: VIDEOS_REQUIRED }, () => video());
const cleanDay = { homeAds: 0, seek: true, quality: true, autoplay: true };
const WANTED = ["a", "b"];
const armHeld = { wanted: WANTED, start: WANTED, end: WANTED, readsIssuer: true, scriptletDocuments: VIDEOS_REQUIRED };

describe("the video site live script", () => {
  it("importing it starts nothing", () => {
    expect(startedAtImport).toEqual({ spawn: 0, spawnSync: 0 });
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
    ["a freeze after the first samples, past the range check", times(0, ...Array<number>(14).fill(6)), "fail"],
    ["playing, then frozen for most of the watch", times(1, 3, 5, 7, 9, 11, ...Array<number>(9).fill(11)), "fail"],
    ["played before the first sample, frozen, moving only at the end", times(...Array<number>(12).fill(5), 7, 9, 11), "fail"],
    ["played before the first sample, frozen, one jump at the end", times(...Array<number>(14).fill(5), 11), "fail"],
    ["the same freeze one sample later", times(3, ...Array<number>(11).fill(5), 7, 9, 11), "fail"],
    ["slow to start, then playing to the end", times(...Array<number>(9).fill(0), 1, 3, 5, 7, 9, 11), "pass"],
    ["at 0 for one sample, then playing", times(0, 2, 4, 6, 8, 10), "pass"],
    ["slow to start, then frozen", times(0, 0, 0, 6, ...Array<number>(11).fill(6)), "fail"],
    ["a short buffering pause", times(1, 3, 5, 5, 7, 9), "pass"],
    ["never played", [sample(0), sample(0)], "unplayed"],
    ["no player", [sample(null), sample(null)], "unplayed"],
    ["no samples", [], "unplayed"],
  ])("a video: %s", (_, samples, verdict) => {
    expect(videoVerdict(samples).verdict).toBe(verdict);
  });

  it("a run passes only with ten played, through the engine, with a scriptlet served", () => {
    expect(runVerdict(tenPasses(), cleanDay, armHeld).verdict).toBe("pass");
    expect(runVerdict(tenPasses().slice(1), cleanDay, armHeld).verdict).toBe("inconclusive");
    const withUnplayed = [...tenPasses().slice(1), video({ verdict: "unplayed" })];
    expect(runVerdict(withUnplayed, cleanDay, armHeld).verdict).toBe("inconclusive");
  });

  it.each([
    ["the wrong issuer", { issuer: "A Public CA" }],
    ["no issuer known", { issuer: null }],
    ["http/3", { protocol: "h3" }],
  ])("a run with %s is inconclusive, never pass, and never a fail either", (_, extra) => {
    expect(runVerdict([...tenPasses().slice(1), video(extra)], cleanDay, armHeld).verdict).toBe("inconclusive");
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail", ...extra })], cleanDay, armHeld).verdict).toBe("inconclusive");
  });

  it.each([
    ["one document short of the videos played", VIDEOS_REQUIRED - 1],
    ["none served", 0],
    ["a meter that could not be read", null],
    ["a meter not reported at all", undefined],
  ])("the engine's meter is the scriptlet witness: %s is inconclusive, never pass, never a fail", (_, scriptlets) => {
    const run = { ...armHeld, scriptletDocuments: scriptlets };
    const said = runVerdict(tenPasses(), cleanDay, run);
    expect(said.verdict).toBe("inconclusive");
    expect(said.reasons.join()).toMatch(/scriptlet/);
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail" })], cleanDay, run).verdict).toBe("inconclusive");
  });

  it("the meter is held to the videos that played, so an unplayed one does not ask for a document", () => {
    const nine = [...tenPasses().slice(1), video({ verdict: "unplayed" })];
    expect(runVerdict(nine, cleanDay, { ...armHeld, scriptletDocuments: 9 }).reasons).toEqual(["9 of 10 videos played"]);
  });

  it("a browser that reports no issuer is witnessed by the meter alone; one that does is still held to it", () => {
    const firefox = tenPasses().map((v) => ({ ...v, issuer: null }));
    expect(runVerdict(firefox, cleanDay, { ...armHeld, readsIssuer: false }).verdict).toBe("pass");
    expect(runVerdict(firefox, cleanDay, { ...armHeld, readsIssuer: false, scriptletDocuments: 0 }).verdict).toBe("inconclusive");
    expect(runVerdict(firefox, cleanDay, armHeld).verdict).toBe("inconclusive");
    expect(runVerdict(firefox, cleanDay, { ...armHeld, readsIssuer: undefined }).verdict, "not saying is not leave").toBe("inconclusive");
    expect(BidiDriver.readsIssuer).toBe(false);
    expect(CdpDriver.readsIssuer).toBe(true);
  });

  it("the documents served are the meter's growth; unread, or a meter that went back, is unknown", () => {
    const status = (n: unknown) => ({ content: { with_scriptlets: n } });
    expect(scriptletDocuments(status(4), status(14))).toBe(10);
    expect(scriptletDocuments(status(4), status(4))).toBe(0);
    expect(scriptletDocuments(status(14), status(1)), "the engine restarted during the run").toBeNull();
    expect(scriptletDocuments(null, status(1))).toBeNull();
    expect(scriptletDocuments(status(1), null)).toBeNull();
    expect(scriptletDocuments({}, status(1))).toBeNull();
    expect(read("engine/crates/sieve-engine/src/stack/mod.rs")).toContain('"with_scriptlets": self.with_scriptlets');
    expect(read("engine/crates/sieve-engine/src/control/mod.rs"), "it is the status file's section").toContain('status["content"]');
  });

  it("nothing a page's own script can write is read as a witness", () => {
    const source = read(SCRIPT);
    expect(source).not.toContain("document.head");
    expect(source).not.toContain("textContent");
  });

  it("a status is read only after the engine has had time to rewrite the file", () => {
    const every = /STATUS_FILE_EVERY_MS: u64 = ([\d_]+)/.exec(read("engine/crates/sieve-engine/src/control/mod.rs"));
    expect(STATUS_SETTLE_MS).toBeGreaterThan(Number(every?.[1].replaceAll("_", "")));
  });

  it.each([
    ["no lists at the end", { start: WANTED, end: [] }],
    ["unreadable status at the end", { start: WANTED, end: null }],
    ["unreadable status at the start", { start: null, end: WANTED }],
    ["one list short", { start: WANTED, end: ["a"] }],
    ["one list too many", { start: WANTED, end: ["a", "b", "c"] }],
    ["another arm's lists", { start: ["x", "y"], end: ["x", "y"] }],
    ["the lists swapped during the run", { start: ["x", "y"], end: WANTED }],
  ])("a run with %s is not evidence about the arm: inconclusive, never pass, never a fail", (_, held) => {
    const lists = { ...armHeld, ...held };
    expect(runVerdict(tenPasses(), cleanDay, lists).verdict).toBe("inconclusive");
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail" })], cleanDay, lists).verdict).toBe("inconclusive");
  });

  it("the lists the engine holds may come in any order", () => {
    expect(runVerdict(tenPasses(), cleanDay, { ...armHeld, start: ["b", "a"], end: ["b", "a"] }).verdict).toBe("pass");
  });

  it("the held lists are read from the shape the engine writes; absent is unknown, not none", () => {
    expect(heldLists({ filter: { lists: [{ id: "a" }, { id: "b" }] } })).toEqual(["a", "b"]);
    expect(heldLists({ filter: { lists: [] } })).toEqual([]);
    expect(heldLists({ filter: null })).toBeNull();
    expect(heldLists({})).toBeNull();
    expect(heldLists(null)).toBeNull();
    const ipc = read("engine/crates/sieve-ipc/src/lib.rs");
    expect(ipc).toContain("pub filter: Option<FilterFacts>");
    expect(ipc).toContain("pub lists: Vec<ListFact>");
  });

  it("a video or a day-one item that fails fails the run", () => {
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail" })], cleanDay, armHeld).verdict).toBe("fail");
    for (const day of [{ homeAds: 1 }, { seek: false }, { quality: false }, { autoplay: false }]) expect(runVerdict(tenPasses(), { ...cleanDay, ...day }, armHeld).verdict).toBe("fail");
    expect(runVerdict(tenPasses(), cleanDay, armHeld).verdict).toBe("pass");
  });

  it.each([
    ["the home page", { homeAds: null }],
    ["seek", { seek: null }],
    ["quality", { quality: null }],
    ["autoplay", { autoplay: null }],
  ])("a day-one check of %s that could not run is unknown: inconclusive, never clean", (_, unknown) => {
    expect(runVerdict(tenPasses(), { ...cleanDay, ...unknown }, armHeld).verdict).toBe("inconclusive");
  });

  it("a day with no checks at all is unknown, and what was seen to fail still fails beside an unknown", () => {
    expect(runVerdict(tenPasses(), {}, armHeld).verdict).toBe("inconclusive");
    expect(runVerdict(tenPasses(), { ...cleanDay, homeAds: null, seek: false }, armHeld).verdict).toBe("fail");
    expect(runVerdict([...tenPasses().slice(1), video({ verdict: "fail" })], { ...cleanDay, homeAds: null }, armHeld).verdict).toBe("fail");
  });

  it("parseArgs refuses an unknown browser, arm or flag", () => {
    const good = ["--browser", "chrome", "--arm", "adguard", "--out", "x"];
    expect(parseArgs(good)).toMatchObject({ browser: "chrome", arm: "adguard", out: "x" });
    expect(() => parseArgs(["--browser", "safari", "--arm", "adguard", "--out", "x"])).toThrow(/browser/);
    expect(() => parseArgs(["--browser", "chrome", "--arm", "ubo", "--out", "x"])).toThrow(/arm/);
    expect(() => parseArgs(["--browser", "chrome", "--arm", "adguard"])).toThrow(/out/);
    expect(() => parseArgs([...good, "--nope", "1"])).toThrow(/nope/);
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

/** Speaks JSON-RPC from a table: a method's answer, or an Error for a refused call. */
class FakeSocket {
  static answers: Record<string, unknown> = {};
  static refuse = false;
  static last: FakeSocket;
  private listeners = new Map<string, ((event: unknown) => void)[]>();

  constructor() {
    FakeSocket.last = this;
    queueMicrotask(() => this.fire(FakeSocket.refuse ? "error" : "open", {}));
  }

  addEventListener(type: string, listener: (event: unknown) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  send(text: string) {
    const { id, method } = JSON.parse(text);
    const answer = FakeSocket.answers[method] ?? {};
    this.deliver(answer instanceof Error ? { id, error: { message: answer.message } } : { id, result: answer });
  }

  close() {}

  deliver(message: unknown) {
    this.fire("message", { data: JSON.stringify(message) });
  }

  private fire(type: string, event: unknown) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

const CDP_ANSWERS = {
  "Target.createTarget": { targetId: "t" },
  "Target.attachToTarget": { sessionId: "s" },
  "Page.getFrameTree": { frameTree: { frame: { id: "main" } } },
};
const BIDI_ANSWERS = {
  "browsingContext.getTree": { contexts: [{ context: "top" }] },
};
const PID = 4242;
const KILLED = [["/PID", String(PID), "/T", "/F"]];
const BIDI_LINE = "WebDriver BiDi listening on ws://127.0.0.1:1\n";

describe("the script's drivers, against a fake socket", () => {
  let profile: string;
  let child: { pid: number; stderr: EventEmitter };
  const work = () => "worked";

  beforeEach(() => {
    profile = mkdtempSync(join(tmpdir(), "sieve-youtube-law-"));
    child = { pid: PID, stderr: new EventEmitter() };
    started.child = child;
    started.spawnSync.length = 0;
    FakeSocket.answers = {};
    FakeSocket.refuse = false;
    vi.stubGlobal("WebSocket", FakeSocket);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    started.child = null;
    rmSync(profile, { recursive: true, force: true });
  });

  const portFile = () => writeFileSync(join(profile, "DevToolsActivePort"), "1\n/devtools/browser/x");

  it("a browser that ran is killed by process tree at the end", async () => {
    portFile();
    FakeSocket.answers = CDP_ANSWERS;
    await expect(withBrowser(CdpDriver, "chrome.exe", profile, work)).resolves.toBe("worked");
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("a browser whose run throws is killed", async () => {
    portFile();
    FakeSocket.answers = CDP_ANSWERS;
    const thrower = () => Promise.reject(new Error("in the run"));
    await expect(withBrowser(CdpDriver, "chrome.exe", profile, thrower)).rejects.toThrow("in the run");
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("chrome: no debugging port, and the browser is killed", async () => {
    vi.useFakeTimers();
    const run = expect(withBrowser(CdpDriver, "chrome.exe", profile, work)).rejects.toThrow(/debugging port/);
    await vi.advanceTimersByTimeAsync(60_000);
    await run;
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("chrome: the socket refuses, and the browser is killed", async () => {
    portFile();
    FakeSocket.refuse = true;
    await expect(withBrowser(CdpDriver, "chrome.exe", profile, work)).rejects.toThrow(/cannot open/);
    expect(started.spawnSync).toEqual(KILLED);
  });

  it.each(["Target.createTarget", "Page.getFrameTree", "Network.enable"])("chrome: %s fails, and the browser is killed", async (method) => {
    portFile();
    FakeSocket.answers = { ...CDP_ANSWERS, [method]: new Error("refused") };
    await expect(withBrowser(CdpDriver, "chrome.exe", profile, work)).rejects.toThrow(/refused/);
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("firefox: no BiDi line, and the browser is killed", async () => {
    vi.useFakeTimers();
    const run = expect(withBrowser(BidiDriver, "firefox.exe", profile, work)).rejects.toThrow(/BiDi port/);
    await vi.advanceTimersByTimeAsync(60_000);
    await run;
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("firefox: the socket refuses, and the browser is killed", async () => {
    FakeSocket.refuse = true;
    const run = withBrowser(BidiDriver, "firefox.exe", profile, work);
    child.stderr.emit("data", BIDI_LINE);
    await expect(run).rejects.toThrow(/cannot open/);
    expect(started.spawnSync).toEqual(KILLED);
  });

  it("firefox: a BiDi call fails, and the browser is killed", async () => {
    FakeSocket.answers = { ...BIDI_ANSWERS, "session.subscribe": new Error("refused") };
    const run = withBrowser(BidiDriver, "firefox.exe", profile, work);
    child.stderr.emit("data", BIDI_LINE);
    await expect(run).rejects.toThrow(/refused/);
    expect(started.spawnSync).toEqual(KILLED);
  });

  const cdpDocument = (frameId: string, issuer: string, protocol = "h2") => ({
    method: "Network.responseReceived",
    params: { type: "Document", frameId, response: { protocol, securityDetails: { issuer } } },
  });

  async function cdpDriver() {
    portFile();
    FakeSocket.answers = CDP_ANSWERS;
    return CdpDriver.connect(child, profile);
  }

  it("chrome: a subframe's response says nothing about the page, either way round", async () => {
    const driver = await cdpDriver();
    FakeSocket.last.deliver(cdpDocument("main", SIEVE_ISSUER));
    FakeSocket.last.deliver(cdpDocument("an-iframe", "A Public CA", "h3"));
    expect(driver.documentFacts()).toEqual({ issuer: SIEVE_ISSUER, protocol: "h2" });
    FakeSocket.last.deliver(cdpDocument("main", "A Public CA"));
    FakeSocket.last.deliver(cdpDocument("an-iframe", SIEVE_ISSUER));
    expect(driver.documentFacts()).toEqual({ issuer: "A Public CA", protocol: "h2" });
  });

  it("chrome: a navigation with no document seen knows nothing, and keeps nothing from the last page", async () => {
    const driver = await cdpDriver();
    FakeSocket.last.deliver(cdpDocument("main", SIEVE_ISSUER));
    vi.useFakeTimers();
    const navigated = driver.navigate("https://x.example/");
    await vi.advanceTimersByTimeAsync(60_000);
    await navigated;
    expect(driver.documentFacts()).toEqual({ issuer: null, protocol: null });
  });

  const bidiDocument = (context: string, protocol: string) => ({
    method: "network.responseCompleted",
    params: { context, navigation: "n", response: { protocol } },
  });

  it("firefox: a subframe's response says nothing about the page, and a navigation forgets the last", async () => {
    FakeSocket.answers = BIDI_ANSWERS;
    const connecting = BidiDriver.connect(child);
    child.stderr.emit("data", BIDI_LINE);
    const driver = await connecting;
    FakeSocket.last.deliver(bidiDocument("top", "h3"));
    FakeSocket.last.deliver(bidiDocument("an-iframe", "h2"));
    expect(driver.documentFacts()).toEqual({ issuer: null, protocol: "h3" });
    vi.useFakeTimers();
    const navigated = driver.navigate("https://x.example/");
    await vi.advanceTimersByTimeAsync(60_000);
    await navigated;
    vi.useRealTimers();
    expect(driver.documentFacts()).toEqual({ issuer: null, protocol: null });
  });
});
