import { describe, expect, it } from "vitest";
import { activeRoute, ROUTES } from "./routes";

describe("routes", () => {
  it("lists Home first and matches paths with or without trailing slashes", () => {
    expect(ROUTES[0].href).toBe("/");
    expect(activeRoute("/")?.href).toBe("/");
    expect(activeRoute("/nowhere/")).toBeUndefined();
  });

  it("every route href is unique", () => {
    expect(new Set(ROUTES.map((r) => r.href)).size).toBe(ROUTES.length);
  });
});
