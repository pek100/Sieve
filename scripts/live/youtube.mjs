// Live check of plan 5.7, slice 10: the video site plays with no ad, through the
// engine, in Chrome, Edge and Firefox, for one arm of the default list set. Run by
// a person with the engine routing, over the real network, under the GPU lease:
// docs/live/engine-slice-10.md. Never run in CI. Site knowledge lives in this file
// and its videos file only, never in the product (engine/tests/no_site_names.rs).
//
// A run is inconclusive, never pass, when it cannot show the engine was in the path
// doing the work with the arm's lists, or a check could not run: see runVerdict.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const BROWSERS = ["chrome", "edge", "firefox"];
export const ARMS = ["adguard", "adguard+ubo"];
export const VIDEOS_REQUIRED = 10;
export const SIEVE_ISSUER = "Sieve local filtering CA";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "../../src/data/fixtures/filter-lists-v1.json");
const DEFAULT_VIDEOS = join(HERE, "youtube-videos.json");
const STATUS_FILE = join(process.env.ProgramData ?? "C:\\ProgramData", "Sieve", "engine", "status.json");
const HOME_URL = "https://www.youtube.com/";
const WATCH_URL = "https://www.youtube.com/watch?v=";

const SAMPLE_MS = 2_000;
const SAMPLES_PER_VIDEO = 15;
const MIN_ADVANCE_S = 5;
const SETTLE_MS = 5_000;
const CALL_TIMEOUT_MS = 30_000;
const START_TIMEOUT_MS = 30_000;
const NEXT_VIDEO_TIMEOUT_MS = 30_000;
/** A player that rose in fewer than this share of its intervals froze, whatever its range. */
const MIN_ADVANCING_SHARE = 0.5;
/** Past the engine's rewrite of status.json (STATUS_FILE_EVERY_MS, held by a law). */
export const STATUS_SETTLE_MS = 35_000;
const SEEK_BY_S = 30;
const LOWER_QUALITY = "small";
const DAY_CHECKS = ["seek", "quality", "autoplay"];

const PLAYER_STATE = `(() => {
  const video = document.querySelector("video.html5-main-video") ?? document.querySelector("video");
  const player = document.querySelector("#movie_player");
  return {
    currentTime: video ? video.currentTime : null,
    adShowing: Boolean(player && (player.classList.contains("ad-showing") || player.classList.contains("ad-interrupting"))),
    enforcement: Boolean(document.querySelector("ytd-enforcement-message-view-model, tp-yt-paper-dialog ytd-enforcement-message-view-model")),
  };
})()`;
// Ads a person can see. A rule's display:none and a blocked fetch's empty slot leave the
// node in the DOM. Its children are measured too: a display:contents wrapper has no box.
// Also hidden: no opacity, clipped by a parent collapsed to nothing, or wholly above or
// left of the page, where no scroll reaches. Any other way stays counted, so a doubt here
// fails a run and never passes one: an out-of-flow box may escape its parent's clip, so
// it counts, and a box past the page's right or bottom end can be scrolled to.
export const HOME_ADS = `(() => {
  const clippedAway = (el) => {
    for (let at = el; at.parentElement && !["absolute", "fixed"].includes(getComputedStyle(at).position); at = at.parentElement) {
      const style = getComputedStyle(at.parentElement);
      const box = at.parentElement.getBoundingClientRect();
      if (style.display !== "contents" && ((box.height === 0 && style.overflowY !== "visible") || (box.width === 0 && style.overflowX !== "visible"))) return true;
    }
    return false;
  };
  const shown = (el) => {
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0 && box.right + scrollX > 0 && box.bottom + scrollY > 0 && el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) && !clippedAway(el);
  };
  return [...document.querySelectorAll("ytd-ad-slot-renderer, ytd-in-feed-ad-layout-renderer, #masthead-ad, ytd-banner-promo-renderer")].filter((ad) => [ad, ...ad.querySelectorAll("*")].some(shown)).length;
})()`;
const SEEK = `(() => { const v = document.querySelector("video"); const before = v.currentTime; v.currentTime = before + ${SEEK_BY_S}; return before; })()`;
const CURRENT_TIME = `document.querySelector("video").currentTime`;
const SET_QUALITY = `(() => { const p = document.querySelector("#movie_player"); p.setPlaybackQualityRange("${LOWER_QUALITY}"); return true; })()`;
const READ_QUALITY = `document.querySelector("#movie_player").getPlaybackQuality()`;
const NEAR_END = `(() => { const v = document.querySelector("video"); v.currentTime = v.duration - 3; return location.href; })()`;
const LOCATION = "location.href";
const USAGE = `node scripts/live/youtube.mjs --browser ${BROWSERS.join("|")} --arm ${ARMS.join("|")} --out <dir> [--videos <json>]`;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The command line. Throws on anything it does not know. */
export function parseArgs(argv) {
  const args = { videos: DEFAULT_VIDEOS };
  const known = new Set(["--browser", "--arm", "--out", "--videos"]);
  for (let i = 0; i < argv.length; i += 2) {
    if (!known.has(argv[i]) || argv[i + 1] === undefined) throw new Error(`bad argument ${argv[i]}: ${USAGE}`);
    args[argv[i].slice(2)] = argv[i + 1];
  }
  if (!BROWSERS.includes(args.browser)) throw new Error(`--browser must be one of ${BROWSERS.join(", ")}`);
  if (!ARMS.includes(args.arm)) throw new Error(`--arm must be one of ${ARMS.join(", ")}`);
  if (!args.out) throw new Error(`--out is required: ${USAGE}`);
  return args;
}

/** An arm's list ids, from each row's `default` in the fixture catalogue.rs is held to by law 13. */
export function armLists(fixture, arm) {
  if (!ARMS.includes(arm)) throw new Error(`unknown arm ${arm}`);
  const wanted = arm === "adguard" ? ["on"] : ["on", "gated"];
  return fixture.examples.pending.lists.filter((row) => wanted.includes(row.default)).map((row) => row.id);
}

/** One video from its samples: pass, fail, or unplayed when no time ever passed. */
export function videoVerdict(samples) {
  const times = samples.map((s) => s.currentTime).filter((t) => typeof t === "number");
  if (samples.some((s) => s.adShowing)) return { verdict: "fail", reason: "the player carried its ad state" };
  if (samples.some((s) => s.enforcement)) return { verdict: "fail", reason: "an enforcement message showed" };
  if (times.length === 0 || Math.max(...times) === 0) return { verdict: "unplayed", reason: "no playback seen" };
  if (Math.max(...times) - Math.min(...times) < MIN_ADVANCE_S) return { verdict: "fail", reason: "currentTime stuck" };
  // A page slow to start sits at 0, and that is not a stall, so the intervals count from
  // its last 0. A first sample past 0 has been playing: a flat run from there is a freeze.
  const playing = times.slice(Math.max(0, times.findIndex((t) => t > 0) - 1));
  const rose = playing.slice(1).filter((t, i) => t > playing[i]).length;
  if (rose < (playing.length - 1) * MIN_ADVANCING_SHARE) return { verdict: "fail", reason: "currentTime stuck" };
  return { verdict: "pass", reason: "advancing and clean" };
}

/** The ids the engine reports holding; null, not none, when the status does not say. */
export function heldLists(status) {
  return status?.filter?.lists?.map((list) => list.id) ?? null;
}

function sameLists(wanted, held) {
  return held !== null && held.length === wanted.length && wanted.every((id) => held.includes(id));
}

/** How many documents the engine put scriptlets in between two statuses. Unknown, not
 *  a number, when either cannot say or the meter went back: the engine restarted. */
export function scriptletDocuments(before, after) {
  const from = before?.content?.with_scriptlets;
  const to = after?.content?.with_scriptlets;
  return typeof from === "number" && typeof to === "number" && to >= from ? to - from : null;
}

/** What a run can claim. Without the engine in the path, the arm's lists held from
 *  start to end, and a scriptlet served, an ad-free video says nothing about Sieve or
 *  this arm, so that is inconclusive before any fail. A failure seen comes next. Then
 *  whatever is unknown keeps it from a pass: a check that could not run is not clean.
 *  The witness of scriptlets is the engine's own meter (`run.scriptletDocuments`),
 *  which no site's script can move. It counts the machine, not this browser. */
export function runVerdict(videos, day, run) {
  const reasons = [];
  if (run.readsIssuer !== false && videos.some((v) => v.issuer !== SIEVE_ISSUER)) reasons.push("a document's issuer is not Sieve's");
  if (videos.some((v) => v.protocol === "h3")) reasons.push("a document came over HTTP/3, which is never decrypted");
  const watched = videos.filter((v) => v.verdict !== "unplayed").length;
  if (typeof run.scriptletDocuments !== "number") reasons.push("the engine's scriptlet meter could not be read");
  else if (run.scriptletDocuments < watched) reasons.push(`the engine put scriptlets in ${run.scriptletDocuments} document(s) for ${watched} video(s) played`);
  for (const moment of ["start", "end"]) {
    if (!sameLists(run.wanted, run[moment])) reasons.push(`at the ${moment} the engine held ${run[moment]?.join(", ") ?? "an unknown set"}, not this arm's ${run.wanted.join(", ")}`);
  }
  if (reasons.length > 0) return { verdict: "inconclusive", reasons };

  const failed = videos.filter((v) => v.verdict === "fail").map((v) => `${v.id}: ${v.reason}`);
  if (day.homeAds > 0) failed.push(`${day.homeAds} ad element(s) on the home page`);
  for (const check of DAY_CHECKS) if (day[check] === false) failed.push(`${check} did not work`);
  if (failed.length > 0) return { verdict: "fail", reasons: failed };

  const played = videos.filter((v) => v.verdict === "pass").length;
  if (played < VIDEOS_REQUIRED) reasons.push(`${played} of ${VIDEOS_REQUIRED} videos played`);
  if (typeof day.homeAds !== "number") reasons.push("the home page could not be checked");
  for (const check of DAY_CHECKS) if (typeof day[check] !== "boolean") reasons.push(`${check} could not be checked`);
  return reasons.length > 0 ? { verdict: "inconclusive", reasons } : { verdict: "pass", reasons };
}

/** Counts per list across a run. Unknown stays null, never 0. */
export function hitsDelta(before, after) {
  if (before === null || after === null) return null;
  const delta = {};
  for (const [list, count] of Object.entries(after)) {
    const grown = count - (before[list] ?? 0);
    if (grown > 0) delta[list] = grown;
  }
  return delta;
}

/** http/3 as each browser writes it. */
export function normalProtocol(protocol) {
  return /^(h3|http\/3)/i.test(protocol ?? "") ? "h3" : protocol ?? null;
}

function readStatus() {
  try {
    return JSON.parse(readFileSync(STATUS_FILE, "utf8"));
  } catch {
    return null;
  }
}

/** The file once the engine has rewritten it, so its meters hold what just happened. */
async function settledStatus() {
  await sleep(STATUS_SETTLE_MS);
  return readStatus();
}

/** What a driver knows of the page's document before its response is seen. */
const NO_DOCUMENT = { issuer: null, protocol: null };

/** One JSON-RPC connection, as CDP and BiDi both speak it. */
class Rpc {
  constructor(socket, onEvent) {
    this.socket = socket;
    this.pending = new Map();
    this.next = 1;
    socket.addEventListener("message", (message) => {
      const data = JSON.parse(message.data);
      const waiting = data.id !== undefined ? this.pending.get(data.id) : undefined;
      if (waiting) {
        this.pending.delete(data.id);
        if (data.error) waiting.reject(new Error(JSON.stringify(data.error)));
        else waiting.resolve(data.result);
      } else {
        onEvent(data);
      }
    });
  }

  static async open(url, onEvent) {
    const socket = new WebSocket(url);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new Error(`cannot open ${url}`)), { once: true });
    });
    return new Rpc(socket, onEvent);
  }

  call(method, params, extra = {}) {
    const id = this.next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${method} timed out`)), CALL_TIMEOUT_MS);
      const done = (fn) => (value) => {
        clearTimeout(timer);
        fn(value);
      };
      this.pending.set(id, { resolve: done(resolve), reject: done(reject) });
      this.socket.send(JSON.stringify({ id, method, params, ...extra }));
    });
  }

  close() {
    this.socket.close();
  }
}

/** Chrome and Edge. */
export class CdpDriver {
  static readsIssuer = true;

  static launch(executable, profile) {
    return spawn(executable, [`--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", "--autoplay-policy=no-user-gesture-required", "about:blank"], { stdio: "ignore" });
  }

  static async connect(child, profile) {
    const portFile = join(profile, "DevToolsActivePort");
    const started = Date.now();
    while (!existsSync(portFile)) {
      if (Date.now() - started > START_TIMEOUT_MS) throw new Error("the browser opened no debugging port");
      await sleep(200);
    }
    const [port, path] = readFileSync(portFile, "utf8").split("\n");
    const driver = new CdpDriver();
    driver.document = NO_DOCUMENT;
    driver.rpc = await Rpc.open(`ws://127.0.0.1:${port.trim()}${path.trim()}`, (event) => driver.onEvent(event));
    const { targetId } = await driver.rpc.call("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await driver.rpc.call("Target.attachToTarget", { targetId, flatten: true });
    driver.session = sessionId;
    await driver.page("Page.enable");
    const { frameTree } = await driver.page("Page.getFrameTree");
    driver.mainFrame = frameTree.frame.id;
    await driver.page("Runtime.enable");
    await driver.page("Network.enable");
    return driver;
  }

  page(method, params = {}) {
    return this.rpc.call(method, params, { sessionId: this.session });
  }

  onEvent({ method, params }) {
    if (method === "Network.responseReceived" && params.type === "Document" && params.frameId === this.mainFrame) {
      this.document = { issuer: params.response.securityDetails?.issuer ?? null, protocol: normalProtocol(params.response.protocol) };
    }
  }

  async navigate(url) {
    this.document = NO_DOCUMENT;
    await this.page("Page.navigate", { url });
    await sleep(SETTLE_MS);
  }

  async evaluate(expression) {
    const { result, exceptionDetails } = await this.page("Runtime.evaluate", { expression, returnByValue: true });
    if (exceptionDetails) throw new Error(exceptionDetails.text);
    return result.value;
  }

  async screenshot() {
    const { data } = await this.page("Page.captureScreenshot", { format: "png" });
    return Buffer.from(data, "base64");
  }

  documentFacts() {
    return this.document;
  }
}

/** Firefox has no CDP. BiDi reports no certificate, so the issuer stays unknown and the
 *  engine's scriptlet meter stands in for it (runVerdict): what is in the page cannot,
 *  since a site's own script can have the same shape. */
export class BidiDriver {
  static readsIssuer = false;

  static launch(executable, profile) {
    return spawn(executable, ["--profile", profile, "--no-remote", "--remote-debugging-port=0", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
  }

  static async connect(child) {
    const url = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("the browser opened no BiDi port")), START_TIMEOUT_MS);
      let seen = "";
      child.stderr.on("data", (chunk) => {
        seen += chunk;
        const found = /WebDriver BiDi listening on (ws:\/\/\S+)/.exec(seen);
        if (found) {
          clearTimeout(timer);
          resolve(found[1]);
        }
      });
    });
    const driver = new BidiDriver();
    driver.document = NO_DOCUMENT;
    driver.rpc = await Rpc.open(`${url}/session`, (event) => driver.onEvent(event));
    await driver.rpc.call("session.new", { capabilities: {} });
    await driver.rpc.call("session.subscribe", { events: ["network.responseCompleted"] });
    const { contexts } = await driver.rpc.call("browsingContext.getTree", {});
    driver.context = contexts[0].context;
    return driver;
  }

  onEvent({ method, params }) {
    if (method === "network.responseCompleted" && params.navigation && params.context === this.context) {
      this.document = { issuer: null, protocol: normalProtocol(params.response.protocol) };
    }
  }

  async navigate(url) {
    this.document = NO_DOCUMENT;
    await this.rpc.call("browsingContext.navigate", { context: this.context, url, wait: "complete" });
    await sleep(SETTLE_MS);
  }

  async evaluate(expression) {
    const answer = await this.rpc.call("script.evaluate", { expression: `JSON.stringify(${expression})`, target: { context: this.context }, awaitPromise: true });
    if (answer.type === "exception") throw new Error(answer.exceptionDetails.text);
    return JSON.parse(answer.result.value);
  }

  async screenshot() {
    const { data } = await this.rpc.call("browsingContext.captureScreenshot", { context: this.context });
    return Buffer.from(data, "base64");
  }

  documentFacts() {
    return this.document;
  }
}

const EXECUTABLES = {
  chrome: ["Google\\Chrome\\Application\\chrome.exe"],
  edge: ["Microsoft\\Edge\\Application\\msedge.exe"],
  firefox: ["Mozilla Firefox\\firefox.exe"],
};

function findExecutable(browser) {
  const roots = [process.env.ProgramFiles, process.env["ProgramFiles(x86)"], process.env.LOCALAPPDATA].filter(Boolean);
  const found = roots.flatMap((root) => EXECUTABLES[browser].map((path) => join(root, path))).find(existsSync);
  if (!found) throw new Error(`${browser} was not found`);
  return found;
}

/** Starts a browser and gives its driver to `work`. Whatever throws, from the spawn on,
 *  the process tree ends, since a browser that never answers is a browser still running. */
export async function withBrowser(Driver, executable, profile, work) {
  const child = Driver.launch(executable, profile);
  let driver = null;
  try {
    driver = await Driver.connect(child, profile);
    return await work(driver);
  } finally {
    driver?.rpc.close();
    if (child.pid) spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
  }
}

/** Runs a check. A check that throws did not run: null, never its false or its zero. */
async function attempt(label, errors, check) {
  try {
    return await check();
  } catch (error) {
    errors.push(`${label}: ${error.message}`);
    return null;
  }
}

async function watch(driver, video, out, errors) {
  const samples = [];
  await driver.navigate(`${WATCH_URL}${video}`);
  for (let i = 0; i < SAMPLES_PER_VIDEO; i++) {
    samples.push(await driver.evaluate(PLAYER_STATE));
    await sleep(SAMPLE_MS);
  }
  const { verdict, reason } = videoVerdict(samples);
  const facts = driver.documentFacts();
  if (verdict !== "pass") {
    await attempt("screenshot", errors, async () => writeFileSync(join(out, `${video}.png`), await driver.screenshot()));
  }
  return { id: video, verdict, reason, issuer: facts.issuer, protocol: facts.protocol, samples };
}

async function dayOneChecks(driver, videos, errors) {
  await driver.navigate(HOME_URL);
  const homeAds = await attempt("home ads", errors, () => driver.evaluate(HOME_ADS));
  await driver.navigate(`${WATCH_URL}${videos[0]}`);
  await sleep(SAMPLE_MS);
  const seek = await attempt("seek", errors, async () => {
    const before = await driver.evaluate(SEEK);
    await sleep(SAMPLE_MS);
    return (await driver.evaluate(CURRENT_TIME)) > before + SEEK_BY_S / 2;
  });
  const quality = await attempt("quality", errors, async () => {
    await driver.evaluate(SET_QUALITY);
    await sleep(SAMPLE_MS);
    return (await driver.evaluate(READ_QUALITY)) === LOWER_QUALITY;
  });
  const autoplay = await attempt("autoplay", errors, async () => {
    const from = await driver.evaluate(NEAR_END);
    const started = Date.now();
    while (Date.now() - started < NEXT_VIDEO_TIMEOUT_MS) {
      if ((await driver.evaluate(LOCATION)) !== from) return true;
      await sleep(SAMPLE_MS);
    }
    return false;
  });
  return { homeAds, seek, quality, autoplay };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const fixture = JSON.parse(readFileSync(FIXTURE, "utf8"));
  const lists = armLists(fixture, args.arm);
  const videos = JSON.parse(readFileSync(args.videos, "utf8")).videos;
  mkdirSync(args.out, { recursive: true });
  console.log(`Arm ${args.arm}: the engine must hold ${lists.join(", ")}.`);

  const before = await settledStatus();
  const profile = mkdtempSync(join(tmpdir(), "sieve-youtube-"));
  const errors = [];
  try {
    const Driver = args.browser === "firefox" ? BidiDriver : CdpDriver;
    await withBrowser(Driver, findExecutable(args.browser), profile, async (driver) => {
      const played = [];
      for (const video of videos) played.push(await watch(driver, video, args.out, errors));
      const day = await dayOneChecks(driver, videos, errors);
      const after = await settledStatus();
      const start = heldLists(before);
      const end = heldLists(after);
      const served = scriptletDocuments(before, after);
      const result = {
        browser: args.browser,
        arm: args.arm,
        lists,
        listsHeldAtStart: start,
        listsHeld: end,
        listHits: hitsDelta(before?.content?.list_hits ?? null, after?.content?.list_hits ?? null),
        scriptletDocuments: served,
        day,
        videos: played,
        errors,
        ...runVerdict(played, day, { wanted: lists, start, end, readsIssuer: Driver.readsIssuer, scriptletDocuments: served }),
      };
      writeFileSync(join(args.out, `youtube-${args.browser}-${args.arm}.json`), JSON.stringify(result, null, 2));
      console.log(`${result.verdict}: ${result.reasons.join("; ") || "every check held"}`);
      process.exitCode = result.verdict === "pass" ? 0 : 1;
    });
  } finally {
    rmSync(profile, { recursive: true, force: true, maxRetries: 5 });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(2);
  });
}
