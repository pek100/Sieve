/**
 * Law: the code injected into pages is what was pinned and reviewed (slice 9).
 * The vendored applier hashes to its pin and rebuilds to the checked-in output;
 * the runner around it acts for every operator adblock-rust can emit; the bundle
 * script's output equals the fixture the engine tests load.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { APPLIER_OUTPUT, APPLIER_SOURCE, transpileApplier } from "../../scripts/injected-build.mjs";
import { ROOT, hits, read, walk } from "./files";

const PINNED_SHA256 = "85a6545f0138127eb86bd5a9ac1d5c852c3c74f34b75d9414c153b199de97c6b";
const MPL_HEADER = "This Source Code Form is subject to the terms of the Mozilla Public";
const OBSERVER_SETTLE_MS = 250;

interface Operator {
  type: string;
  arg: string;
}
interface Action {
  type: string;
  arg?: string;
}
interface Filter {
  selector: Operator[];
  action?: Action;
}
type RunProcedural = (applier: unknown, filters: Filter[]) => void;

function loadApplier(): unknown {
  const exports = {};
  new Function("exports", readFileSync(APPLIER_OUTPUT, "utf8"))(exports);
  return exports;
}

function loadBootstrap(): RunProcedural {
  return new Function(`${read("engine/injected/bootstrap.js")}\nreturn sieveRunProcedural;`)() as RunProcedural;
}

const run = (...filters: Filter[]) => loadBootstrap()(loadApplier(), filters);
const css = (arg: string): Operator => ({ type: "css-selector", arg });
const element = (id: string) => document.getElementById(id) as HTMLElement;
const hidden = (id: string) => element(id).style.getPropertyValue("display") === "none" && element(id).style.getPropertyPriority("display") === "important";

describe("the vendored applier", () => {
  it("hashes to its pin, byte for byte", () => {
    expect(createHash("sha256").update(readFileSync(APPLIER_SOURCE)).digest("hex")).toBe(PINNED_SHA256);
  });

  it("rebuilds to the checked-in output", () => {
    expect(transpileApplier()).toBe(readFileSync(APPLIER_OUTPUT, "utf8"));
  });

  it("keeps its MPL header in the source and the output", () => {
    expect(readFileSync(APPLIER_SOURCE, "utf8")).toContain(MPL_HEADER);
    expect(readFileSync(APPLIER_OUTPUT, "utf8")).toContain(MPL_HEADER);
  });
});

/** Runs the script as a user would, under plain node: vitest's import would rewrite `fn.toString()`. */
function assembleFixtureTree(): string {
  const dir = mkdtempSync(join(tmpdir(), "sieve-assemble-"));
  try {
    const out = join(dir, "bundle.json");
    execFileSync("node", ["scripts/resources/assemble-ubo.mjs", "tests/fixtures/ubo-tree", out], { cwd: ROOT, stdio: "pipe" });
    return readFileSync(out, "utf8");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("the bundle script", () => {
  it("writes exactly the fixture bundle from the fixture tree", () => {
    expect(assembleFixtureTree()).toBe(read("engine/crates/sieve-filter/testdata/resources-fixture.json"));
  });

  it("maps trust, kinds and dependencies from uBO's fields", () => {
    const resources = JSON.parse(assembleFixtureTree()) as {
      name: string;
      kind: { mime: string };
      permission?: number;
      dependencies?: string[];
    }[];
    const named = (name: string) => resources.find((r) => r.name === name);
    expect(named("trusted-sieve-flag.js")?.permission).toBe(1);
    expect(named("trusted-sieve-flag.js")?.dependencies).toEqual(["sieve-flag-name.fn"]);
    expect(named("sieve-set-flag.js")?.permission).toBeUndefined();
    expect(named("sieve-flag-name.fn")?.kind.mime).toBe("fn/javascript");
    expect(named("sieve-pixel.gif")?.kind.mime).toBe("image/gif");
    expect(named("sieve-parameterised.js")).toBeUndefined();
  });
});

describe("the bootstrap under jsdom", () => {
  beforeEach(() => {
    // jsdom has no layout, so no innerText; textContent is close enough here.
    Object.defineProperty(HTMLElement.prototype, "innerText", {
      configurable: true,
      get(this: HTMLElement) {
        return this.textContent ?? "";
      },
    });
    document.body.innerHTML = `
      <div id="keep" class="box">plain</div>
      <div id="text" class="box">sponsored link</div>
      <div id="attr" class="box" data-ad="yes">x</div>
      <div id="style" class="box" style="color: red">x</div>
      <div id="long" class="box">a very long piece of text</div>
      <section id="outer"><div id="inner" class="inner">x</div></section>
      <div id="xpath" class="box">x</div>
      <div id="action-remove" class="box">remove me</div>
      <div id="action-style" class="box">style me</div>
      <div id="action-attr" class="box" onclick="x()">attr me</div>
      <div id="action-class" class="box advert">class me</div>`;
  });

  afterEach(() => {
    document.body.innerHTML = "";
    Reflect.deleteProperty(HTMLElement.prototype, "innerText");
  });

  const OPERATORS: [string, Operator[], string][] = [
    ["css-selector then has-text", [css(".box"), { type: "has-text", arg: "sponsored" }], "text"],
    ["has-text with a regex", [css(".box"), { type: "has-text", arg: "/SPONSORED/i" }], "text"],
    ["matches-attr", [css(".box"), { type: "matches-attr", arg: '"data-ad"="yes"' }], "attr"],
    ["matches-css", [css(".box"), { type: "matches-css", arg: "color: rgb(255, 0, 0)" }], "style"],
    ["min-text-length", [css(".box"), { type: "min-text-length", arg: "20" }], "long"],
    ["upward", [css(".inner"), { type: "upward", arg: "1" }], "outer"],
    ["xpath", [{ type: "xpath", arg: "//div[@id='xpath']" }], "xpath"],
  ];

  it.each(OPERATORS)("hides what %s selects, and only that", (_name, selector, id) => {
    run({ selector });
    expect(hidden(id)).toBe(true);
    expect(hidden("keep")).toBe(false);
  });

  it("matches-path gates a filter on the page's path", () => {
    run({ selector: [css("#text"), { type: "matches-path", arg: "/no-such-path" }] });
    expect(hidden("text")).toBe(false);
    run({ selector: [css("#text"), { type: "matches-path", arg: window.location.pathname }] });
    expect(hidden("text")).toBe(true);
  });

  it("matches-css-before and matches-css-after compile and select without throwing", () => {
    // jsdom computes no pseudo-element styles, so a browser must prove the match.
    for (const type of ["matches-css-before", "matches-css-after"]) {
      expect(() => run({ selector: [css("#keep"), { type, arg: "content: none" }] })).not.toThrow();
    }
  });

  it("runs every action", () => {
    run(
      { selector: [css("#action-remove")], action: { type: "remove" } },
      { selector: [css("#action-style")], action: { type: "style", arg: "color: blue" } },
      { selector: [css("#action-attr")], action: { type: "remove-attr", arg: "onclick" } },
      { selector: [css("#action-class")], action: { type: "remove-class", arg: "advert" } },
    );
    expect(document.getElementById("action-remove")).toBeNull();
    expect(element("action-style").style.color).toBe("blue");
    expect(element("action-attr").hasAttribute("onclick")).toBe(false);
    expect(element("action-class").classList.contains("advert")).toBe(false);
    expect(element("action-class").classList.contains("box")).toBe(true);
  });

  it("one filter it cannot compile or apply costs only itself", () => {
    expect(() =>
      run(
        { selector: [{ type: "no-such-operator", arg: "x" }] },
        { selector: [css("#keep"), { type: "matches-css", arg: "not a declaration" }] },
        { selector: [css("#text")] },
      ),
    ).not.toThrow();
    expect(hidden("text")).toBe(true);
  });

  it("catches elements added later, and settles", async () => {
    run({ selector: [css(".late"), { type: "has-text", arg: "ad" }] });
    const late = document.createElement("div");
    const setProperty = vi.spyOn(late.style, "setProperty");
    late.id = "late";
    late.className = "late";
    late.textContent = "ad";
    document.body.append(late);
    await new Promise((resolve) => setTimeout(resolve, OBSERVER_SETTLE_MS));
    expect(hidden("late")).toBe(true);
    expect(setProperty).toHaveBeenCalledTimes(1);
    setProperty.mockClear();
    document.body.append(document.createElement("p"));
    await new Promise((resolve) => setTimeout(resolve, OBSERVER_SETTLE_MS));
    expect(setProperty).not.toHaveBeenCalled();
  });

  it("waits for DOMContentLoaded while the document is loading", () => {
    const readyState = vi.spyOn(document, "readyState", "get").mockReturnValue("loading");
    run({ selector: [css("#text")] });
    expect(hidden("text")).toBe(false);
    readyState.mockReturnValue("interactive");
    document.dispatchEvent(new Event("DOMContentLoaded"));
    expect(hidden("text")).toBe(true);
  });
});

describe("no site names", () => {
  const SITE_NAME = /\b[a-z0-9-]+\.(com|net|org|io|tv|co|dev|app)\b/;
  const SOURCES = [
    ...walk("engine/crates/sieve-engine/src/inject", [".rs"]),
    "engine/crates/sieve-engine/tests/inject_page.rs",
    "engine/crates/sieve-engine/examples/inject_bench.rs",
    "engine/crates/sieve-filter/src/cosmetic.rs",
    "engine/crates/sieve-filter/src/resources.rs",
    "engine/injected/bootstrap.js",
    ...walk("tests/fixtures/ubo-tree", [".js"]),
    "scripts/resources/assemble-ubo.mjs",
  ];

  it("appear in the new source and fixtures", () => {
    expect(SOURCES.flatMap((file) => hits(file, SITE_NAME))).toEqual([]);
  });

  it("would be caught", () => {
    expect(SITE_NAME.test("ads.example.com##.x")).toBe(true);
    expect(SITE_NAME.test("page.sieve-test.invalid##.x")).toBe(false);
  });

  it("the fixture rules name only .invalid hosts", () => {
    const hosts = read("engine/crates/sieve-engine/tests/inject_page.rs").match(/[a-z0-9-]+(\.[a-z0-9-]+)+(?=##|\/article)/g) ?? [];
    expect(hosts.length).toBeGreaterThan(0);
    for (const host of hosts) expect(host.endsWith(".invalid")).toBe(true);
  });
});
