import { describe, expect, it } from "vitest";
import { read, walk } from "../../tests/laws/files";
import { cn, TYPE_ROLES } from "./utils";

describe("cn knows the Sieve type roles", () => {
  it("keeps a type role next to a colour role, in either order", () => {
    expect(cn("text-label text-on-surface-muted")).toBe("text-label text-on-surface-muted");
    expect(cn("text-label", "text-on-surface")).toBe("text-label text-on-surface");
    expect(cn("bg-primary text-on-primary", "h-9 text-label")).toBe("bg-primary text-on-primary h-9 text-label");
  });

  it("still resolves real conflicts", () => {
    expect(cn("text-label", "text-body")).toBe("text-body");
    expect(cn("text-body text-on-surface", "text-label")).toBe("text-on-surface text-label");
    expect(cn("text-on-surface", "text-primary")).toBe("text-primary");
  });

  it("covers every --text-* role in globals.css, and every file merges classes through it", () => {
    const css = read("src/app/globals.css");
    const roles = [...css.matchAll(/^\s*--text-([\w-]+):/gm)].map((m) => m[1]).filter((r) => !r.includes("--"));
    expect(new Set(roles)).toEqual(new Set(TYPE_ROLES));
    const direct = walk("src", [".ts", ".tsx"]).filter((f) => f !== "src/lib/utils.ts" && /^import .* from ["']cn["']/m.test(read(f)));
    expect(direct).toEqual([]);
  });
});
