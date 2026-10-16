import { describe, expect, it } from "vitest";
import { read, walk } from "../../tests/laws/files";
import { cn, TYPE_SCALE } from "./utils";

describe("cn knows the type scale", () => {
  it("keeps a text colour next to a type-scale size, in either order", () => {
    expect(cn("bg-primary text-on-primary", "h-9 text-label")).toBe("bg-primary text-on-primary h-9 text-label");
    expect(cn("text-label", "text-on-surface")).toBe("text-label text-on-surface");
  });

  it("still lets a later size or colour win over an earlier one", () => {
    expect(cn("text-body text-on-surface", "text-label")).toBe("text-on-surface text-label");
    expect(cn("text-on-surface", "text-blocked")).toBe("text-blocked");
  });

  it("lists exactly the --text-* sizes globals.css defines", () => {
    const sizes = [...read("src/app/globals.css").matchAll(/^\s*--text-([a-z]+(?:-[a-z]+)*):/gm)].map((m) => m[1]);
    expect([...TYPE_SCALE].sort()).toEqual([...new Set(sizes)].sort());
  });

  it("every component merges through this cn, not the bare package", () => {
    const bare = walk("src", [".ts", ".tsx"]).filter((f) => f !== "src/lib/utils.ts" && !f.endsWith(".test.ts") && /from "cn"/.test(read(f)));
    expect(bare).toEqual([]);
  });
});
