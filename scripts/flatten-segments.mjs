// Post-build fix for the static export (Next 16.4.2, output: "export").
//
// For a nested route the export writes segment prefetch files into a folder,
// for example out/apps/__next.apps/__PAGE__.txt, but the client router asks
// for the flat name out/apps/__next.apps.__PAGE__.txt. Every static host,
// Tauri's asset server included, then answers 404 and the console shows an
// error on every page that links to the route. This copies each file under a
// `__next.*` folder to its flat sibling name. The root route is already flat.
// Usage: node scripts/flatten-segments.mjs (run by `pnpm build`).
import { copyFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)), "out");

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

function segmentDirs(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (!statSync(p).isDirectory()) return [];
    return name.startsWith("__next.") ? [p] : segmentDirs(p);
  });
}

if (!existsSync(ROOT)) {
  console.error(`flatten-segments: ${ROOT} does not exist. Run \`next build\` first.`);
  process.exit(1);
}

let copied = 0;
for (const dir of segmentDirs(ROOT)) {
  for (const file of files(dir)) {
    const flat = join(dir, "..", `${dir.split(sep).pop()}.${relative(dir, file).split(sep).join(".")}`);
    if (!existsSync(flat)) {
      copyFileSync(file, flat);
      copied += 1;
    }
  }
}
console.log(`flatten-segments: ${copied} segment file(s) copied to flat names`);
