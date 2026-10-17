/** The Next config the desktop window depends on: a static export, no dev indicator bubble. */
import { describe, expect, it } from "vitest";
import nextConfig from "../../next.config";

describe("next config", () => {
  it("exports static files and hides the dev indicator (the 'N' bubble in the dev window)", () => {
    expect(nextConfig.output).toBe("export");
    expect(nextConfig.devIndicators).toBe(false);
  });
});
