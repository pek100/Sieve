import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

async function htmlFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? htmlFiles(path) : path.endsWith(".html") ? [path] : [];
  }));
  return nested.flat();
}

// Check the actual export, including prerendered client components.
const files = await htmlFiles("out");
if (files.length === 0) throw new Error("No exported HTML to check. Run the production build first.");
for (const path of files) {
  if ((await readFile(path, "utf8")).includes("Dev build")) throw new Error(`Development label leaked into ${path}`);
}
console.log(`Release label check: ${files.length} HTML files, no Dev build text.`);
