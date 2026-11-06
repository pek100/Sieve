// Live check of plan 5.7, slice 10: the video site plays with no ad, through the
// engine, in Chrome, Edge and Firefox, for one arm of the default list set. Run by
// a person with the engine routing, over the real network, under the GPU lease:
// docs/live/engine-slice-10.md. Never run in CI. Site knowledge lives in this file
// and its videos file only, never in the product (engine/tests/no_site_names.rs).
//
// A run is inconclusive, never pass, when it cannot show the engine was in the path
// doing the work: see runVerdict.

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
const SEEK_BY_S = 30;
const LOWER_QUALITY = "small";

const PLAYER_STATE = `(() => {
  const video = document.querySelector("video.html5-main-video") ?? document.querySelector("video");
  const player = document.querySelector("#movie_player");
  return {
    currentTime: video ? video.currentTime : null,
    adShowing: Boolean(player && (player.classList.contains("ad-showing") || player.classList.contains("ad-interrupting"))),
    enforcement: Boolean(document.querySelector("ytd-enforcement-message-view-model, tp-yt-paper-dialog ytd-enforcement-message-view-model")),
  };
})()`;
const HOME_ADS = `document.querySelectorAll("ytd-ad-slot-renderer, ytd-in-feed-ad-layout-renderer, #masthead-ad, ytd-banner-promo-renderer").length`;
const FIRST_HEAD_SCRIPT = `(document.head && document.head.querySelector("script") && document.head.querySelector("script").textContent) || ""`;
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
  return { verdict: "pass", reason: "advancing and clean" };
}

/** What a run can claim. Without the engine in the path or a scriptlet served, an
 *  ad-free video says nothing about Sieve, so that is inconclusive before any fail. */
export function runVerdict(videos, day = {}) {
  const reasons = [];
  if (videos.some((v) => v.issuer !== SIEVE_ISSUER)) reasons.push("a document's issuer is not Sieve's");
  if (videos.some((v) => v.protocol === "h3")) reasons.push("a document came over HTTP/3, which is never decrypted");
  if (videos.some((v) => v.verdict !== "unplayed" && !v.scriptletPayload)) reasons.push("no scriptlet payload in a served document");
  if (reasons.length > 0) return { verdict: "inconclusive", reasons };
  const failed = videos.filter((v) => v.verdict === "fail").map((v) => `${v.id}: ${v.reason}`);
  if (day.homeAds > 0) failed.push(`${day.homeAds} ad element(s) on the home page`);
  for (const check of ["seek", "quality", "autoplay"]) if (day[check] === false) failed.push(`${check} did not work`);
  if (failed.length > 0) return { verdict: "fail", reasons: failed };
  const played = videos.filter((v) => v.verdict === "pass").length;
  if (played < VIDEOS_REQUIRED) return { verdict: "inconclusive", reasons: [`${played} of ${VIDEOS_REQUIRED} videos played`] };
  return { verdict: "pass", reasons: [] };
}

/** True when the first script of a page is the engine's and holds scriptlets, not
 *  only the applier (the shape inject/payload.rs writes). */
export function scriptletPayload(scriptText) {
  const body = /^\(function\(\)\{\n([\s\S]*?)(?:\nvar sieveApplier=|\n\}\)\(\);$)/.exec(scriptText);
  return body !== null && body[1].trim().length > 0;
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
class CdpDriver {
  static async start(executable, profile) {
    const child = spawn(executable, [`--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", "--autoplay-policy=no-user-gesture-required", "about:blank"], { stdio: "ignore" });
    const portFile = join(profile, "DevToolsActivePort");
    const started = Date.now();
    while (!existsSync(portFile)) {
      if (Date.now() - started > START_TIMEOUT_MS) throw new Error("the browser opened no debugging port");
      await sleep(200);
    }
    const [port, path] = readFileSync(portFile, "utf8").split("\n");
    const driver = new CdpDriver();
    driver.child = child;
    driver.document = { issuer: null, protocol: null };
    driver.rpc = await Rpc.open(`ws://127.0.0.1:${port.trim()}${path.trim()}`, (event) => driver.onEvent(event));
    const { targetId } = await driver.rpc.call("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await driver.rpc.call("Target.attachToTarget", { targetId, flatten: true });
    driver.session = sessionId;
    await driver.page("Page.enable");
    await driver.page("Runtime.enable");
    await driver.page("Network.enable");
    return driver;
  }

  page(method, params = {}) {
    return this.rpc.call(method, params, { sessionId: this.session });
  }

  onEvent({ method, params }) {
    if (method === "Network.responseReceived" && params.type === "Document") {
      this.document = { issuer: params.response.securityDetails?.issuer ?? null, protocol: normalProtocol(params.response.protocol) };
    }
  }

  async navigate(url) {
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

/** Firefox has no CDP. BiDi reports no certificate, so the issuer is witnessed by the
 *  engine's own script being in the page: nothing else can have put it there. */
class BidiDriver {
  static async start(executable, profile) {
    const child = spawn(executable, ["--profile", profile, "--no-remote", "--remote-debugging-port=0", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
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
    driver.child = child;
    driver.document = { protocol: null };
    driver.rpc = await Rpc.open(`${url}/session`, (event) => driver.onEvent(event));
    await driver.rpc.call("session.new", { capabilities: {} });
    await driver.rpc.call("session.subscribe", { events: ["network.responseCompleted"] });
    const { contexts } = await driver.rpc.call("browsingContext.getTree", {});
    driver.context = contexts[0].context;
    return driver;
  }

  onEvent({ method, params }) {
    if (method === "network.responseCompleted" && params.navigation) {
      this.document = { protocol: normalProtocol(params.response.protocol) };
    }
  }

  async navigate(url) {
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

  async documentFacts() {
    const script = await this.evaluate(FIRST_HEAD_SCRIPT);
    return { issuer: script.startsWith("(function(){\n") ? SIEVE_ISSUER : null, protocol: this.document.protocol };
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

/** Runs a check; a page that refuses it answers false, and a thrown error is recorded. */
async function attempt(label, errors, check) {
  try {
    return await check();
  } catch (error) {
    errors.push(`${label}: ${error.message}`);
    return false;
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
  const facts = await driver.documentFacts();
  const payload = scriptletPayload(await driver.evaluate(FIRST_HEAD_SCRIPT));
  if (verdict !== "pass") {
    await attempt("screenshot", errors, async () => writeFileSync(join(out, `${video}.png`), await driver.screenshot()));
  }
  return { id: video, verdict, reason, issuer: facts.issuer, protocol: facts.protocol, scriptletPayload: payload, samples };
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
  return { homeAds: typeof homeAds === "number" ? homeAds : null, seek, quality, autoplay };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const fixture = JSON.parse(readFileSync(FIXTURE, "utf8"));
  const lists = armLists(fixture, args.arm);
  const videos = JSON.parse(readFileSync(args.videos, "utf8")).videos;
  mkdirSync(args.out, { recursive: true });
  console.log(`Arm ${args.arm}: the engine must hold ${lists.join(", ")}.`);

  const before = readStatus();
  const profile = mkdtempSync(join(tmpdir(), "sieve-youtube-"));
  const errors = [];
  let driver = null;
  try {
    const Driver = args.browser === "firefox" ? BidiDriver : CdpDriver;
    driver = await Driver.start(findExecutable(args.browser), profile);
    const played = [];
    for (const video of videos) played.push(await watch(driver, video, args.out, errors));
    const day = await dayOneChecks(driver, videos, errors);
    const after = readStatus();
    const result = {
      browser: args.browser,
      arm: args.arm,
      lists,
      listsHeld: after?.filter?.lists?.map((l) => l.id) ?? null,
      listHits: hitsDelta(before?.content?.list_hits ?? null, after?.content?.list_hits ?? null),
      day,
      videos: played,
      errors,
      ...runVerdict(played, day),
    };
    writeFileSync(join(args.out, `youtube-${args.browser}-${args.arm}.json`), JSON.stringify(result, null, 2));
    console.log(`${result.verdict}: ${result.reasons.join("; ") || "every check held"}`);
    process.exitCode = result.verdict === "pass" ? 0 : 1;
  } finally {
    driver?.rpc?.close();
    if (driver?.child?.pid) spawnSync("taskkill", ["/PID", String(driver.child.pid), "/T", "/F"], { stdio: "ignore" });
    rmSync(profile, { recursive: true, force: true, maxRetries: 5 });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(2);
  });
}
