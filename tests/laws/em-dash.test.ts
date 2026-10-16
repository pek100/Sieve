/** Law 2: no em dash (U+2014) in code, copy, tests or docs. */
import { describe, expect, it } from "vitest";
import { hits, walk } from "./files";

const EXTS = [".ts", ".tsx", ".css", ".rs", ".md", ".json", ".mjs", ".toml"];
// Built from the code point so this file never contains the character itself.
const EM_DASH = new RegExp(String.fromCharCode(0x2014));

describe("em dash law", () => {
  it("finds no U+2014 anywhere we write", () => {
    const files = [
      ...walk("src", EXTS),
      ...walk("src-tauri/src", EXTS),
      ...walk("docs", EXTS),
      ...walk("tests", EXTS),
      ...walk("scripts", EXTS),
    ];
    expect(files.flatMap((f) => hits(f, EM_DASH))).toEqual([]);
  });
});
