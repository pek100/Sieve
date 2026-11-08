// Assembles the resource bundle the engine pins (docs/tasks/2026-11-02-content.md, D1):
//   node scripts/resources/assemble-ubo.mjs <ubo-checkout> <out.json>
//
// adblock-rust's assembler cannot read a current uBlock Origin (its scriptlets
// are ES modules), so uBO's own modules are imported here under node and written
// as a sorted JSON array of adblock-rust `Resource` values. The engine only
// deserializes the result: nothing in the bundle runs in the service.
import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { argv, exit } from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPTLETS_MODULE = "src/js/resources/scriptlets.js";
const REDIRECTS_MODULE = "src/js/redirect-resources.js";
const REDIRECT_FILES_DIR = "src/web_accessible_resources";
// adblock-rust's PermissionMask bit for "needs a trusted list". The engine gives
// trusted lists every bit and untrusted lists none.
const TRUST_PERMISSION = 1;
// What adblock-rust's extract_function_name needs to call a resource with arguments.
const NAMED_FUNCTION = /^function\s+[^(){}\s]+\s*\(/;
// A dependency is only prepended, never called, so any named declaration will do:
// current uBO declares some as classes (ArglistParser) and async functions.
const NAMED_DECLARATION = /^(?:(?:async\s+)?function\s*\*?\s*[^(){}\s]+\s*\(|class\s+[^\s{]+)/;
const MIME_BY_EXTENSION = new Map([
  ["css", "text/css"],
  ["gif", "image/gif"],
  ["html", "text/html"],
  ["js", "application/javascript"],
  ["json", "application/json"],
  ["mp3", "audio/mp3"],
  ["mp4", "video/mp4"],
  ["png", "image/png"],
  ["txt", "text/plain"],
  ["xml", "text/xml"],
]);
const FUNCTION_SUFFIX = ".fn";

const encodeText = (text) => Buffer.from(text.replace(/\r/g, ""), "utf8").toString("base64");
const asArray = (value) => (value === undefined ? [] : Array.isArray(value) ? value : [value]);
const moduleUrl = (root, path) => pathToFileURL(join(root, path)).href;

function scriptletResource(entry, nameOf) {
  const source = entry.fn.toString();
  const dependency = entry.name.endsWith(FUNCTION_SUFFIX);
  if (!(dependency ? NAMED_DECLARATION : NAMED_FUNCTION).test(source)) {
    throw new Error(`scriptlet ${entry.name} is not a named ${dependency ? "declaration" : "function declaration"}`);
  }
  const resource = {
    name: entry.name,
    aliases: asArray(entry.aliases),
    kind: { mime: dependency ? "fn/javascript" : "application/javascript" },
    content: encodeText(source),
  };
  const dependencies = asArray(entry.dependencies).map(nameOf);
  if (dependencies.length > 0) resource.dependencies = dependencies;
  if (entry.requiresTrust) resource.permission = TRUST_PERMISSION;
  return resource;
}

async function scriptletResources(root) {
  const { builtinScriptlets } = await import(moduleUrl(root, SCRIPTLETS_MODULE));
  const nameByFn = new Map(builtinScriptlets.map((entry) => [entry.fn, entry.name]));
  const nameOf = (dependency) => {
    const name = typeof dependency === "function" ? nameByFn.get(dependency) : dependency;
    if (!name) throw new Error(`unnamed scriptlet dependency: ${dependency}`);
    return name;
  };
  return builtinScriptlets.map((entry) => scriptletResource(entry, nameOf));
}

async function redirectResources(root) {
  const { default: redirects } = await import(moduleUrl(root, REDIRECTS_MODULE));
  const resources = [];
  for (const [name, properties] of redirects) {
    // adblock-rust has no parameterised redirects; its own assembler skips them too.
    if (properties.params) continue;
    const mime = MIME_BY_EXTENSION.get(name.split(".").pop()) ?? "application/octet-stream";
    const bytes = await readFile(join(root, REDIRECT_FILES_DIR, name));
    const content = properties.data === "text" ? encodeText(bytes.toString("utf8")) : bytes.toString("base64");
    resources.push({ name, aliases: asArray(properties.alias), kind: { mime }, content });
  }
  return resources;
}

/** The bundle's bytes: sorted by name, so the same tree always gives the same hash. */
export async function assemble(root) {
  const resources = [...(await scriptletResources(root)), ...(await redirectResources(root))];
  resources.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return `${JSON.stringify(resources, null, 1)}\n`;
}

if (argv[1] && resolve(argv[1]) === fileURLToPath(import.meta.url)) {
  const [root, out] = argv.slice(2);
  if (!root || !out) {
    console.error("usage: assemble-ubo.mjs <ubo-checkout> <out.json>");
    exit(2);
  }
  await writeFile(out, await assemble(resolve(root)));
}
