import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Wordmark } from "./wordmark";

afterEach(() => vi.unstubAllEnvs());

describe("wordmark build identity", () => {
  it("labels a development render", () => {
    vi.stubEnv("NODE_ENV", "development");
    expect(renderToStaticMarkup(<Wordmark />)).toContain("Dev build");
  });

  it("omits the label in a production render", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(renderToStaticMarkup(<Wordmark />)).not.toContain("Dev build");
  });
});
