// Static server for the `out/` export, used by Playwright (and by hand).
// No dependencies beyond node. Port: PORT env or 3417. Binds 127.0.0.1 only.
// Usage: node scripts/serve-out.mjs
import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)), "out");
const PORT = Number(process.env.PORT ?? 3417);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
};

if (!existsSync(ROOT)) {
  console.error(`serve-out: ${ROOT} does not exist. Run \`pnpm build\` first.`);
  process.exit(1);
}

function resolveFile(urlPath) {
  const clean = normalize(decodeURIComponent(urlPath.split("?")[0])).replace(/^([/\\])+/, "");
  const abs = join(ROOT, clean);
  if (abs !== ROOT && !abs.startsWith(ROOT + sep)) return null;
  if (existsSync(abs) && statSync(abs).isFile()) return abs;
  const index = join(abs, "index.html");
  if (existsSync(index)) return index;
  if (existsSync(abs + ".html")) return abs + ".html";
  return null;
}

const server = createServer((req, res) => {
  const file = resolveFile(req.url ?? "/");
  if (!file) {
    res.writeHead(404, { "content-type": TYPES[".html"] });
    createReadStream(join(ROOT, "404.html")).pipe(res);
    return;
  }
  res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(res);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`serve-out: http://127.0.0.1:${PORT}/ (from ${ROOT})`);
});

for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => server.close(() => process.exit(0)));
