/** Shared file walking for the law tests. Paths are repo relative with forward slashes. */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export const ROOT = join(__dirname, "..", "..");

const SKIP = new Set(["node_modules", ".next", "out", "target", "gen", "test-results", ".git"]);

export function walk(dir: string, exts: readonly string[]): string[] {
  const abs = join(ROOT, dir);
  const out: string[] = [];
  const visit = (d: string) => {
    for (const name of readdirSync(d)) {
      if (SKIP.has(name)) continue;
      const p = join(d, name);
      if (statSync(p).isDirectory()) visit(p);
      else if (exts.some((e) => name.endsWith(e))) out.push(relative(ROOT, p).replace(/\\/g, "/"));
    }
  };
  visit(abs);
  return out.sort();
}

export function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8");
}

/** Lines of `rel` matching `re`, as "path:line: text". */
export function hits(rel: string, re: RegExp): string[] {
  return read(rel)
    .split(/\r?\n/)
    .flatMap((line, i) => (re.test(line) ? [`${rel}:${i + 1}: ${line.trim()}`] : []));
}
