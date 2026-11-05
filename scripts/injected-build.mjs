// Transpiles the vendored procedural applier (pnpm injected:build). The output is
// checked in and read with include_str!, so cargo builds never need node.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { argv } from "node:process";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const INJECTED_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "engine", "injected");
export const APPLIER_SOURCE = join(INJECTED_DIR, "procedural_filters.ts");
export const APPLIER_OUTPUT = join(INJECTED_DIR, "procedural-applier.js");

/** The applier as a CommonJS body: the payload supplies `exports`. */
export function transpileApplier() {
  return ts.transpileModule(readFileSync(APPLIER_SOURCE, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      newLine: ts.NewLineKind.LineFeed,
      removeComments: false,
    },
  }).outputText;
}

if (argv[1] && resolve(argv[1]) === fileURLToPath(import.meta.url)) {
  writeFileSync(APPLIER_OUTPUT, transpileApplier());
}
