import { describe, expect, it } from "vitest";
import { tooltipPosition } from "@/components/sieve/primitives/floating-tooltip";

const VW = 1280;
const VH = 800;
const W = 200;
const H = 120;

describe("chart tooltip placement (fixed, follows the cursor, flips at viewport edges)", () => {
  it("sits right of and below the cursor when there is room", () => {
    expect(tooltipPosition(100, 100, W, H, VW, VH)).toEqual({ left: 112, top: 112 });
  });

  it("flips to the left of the cursor near the right edge", () => {
    const p = tooltipPosition(1200, 100, W, H, VW, VH);
    expect(p.left).toBe(1200 - 12 - W);
    expect(p.left + W).toBeLessThanOrEqual(1200);
  });

  it("flips above the cursor near the bottom edge", () => {
    const p = tooltipPosition(100, 760, W, H, VW, VH);
    expect(p.top).toBe(760 - 12 - H);
  });

  it("never leaves the viewport, even when it is wider than the room on either side", () => {
    for (const [x, y] of [
      [0, 0],
      [VW, VH],
      [VW / 2, VH / 2],
      [5, 795],
    ]) {
      const p = tooltipPosition(x, y, 700, 500, VW, VH);
      expect(p.left).toBeGreaterThanOrEqual(8);
      expect(p.top).toBeGreaterThanOrEqual(8);
      expect(p.left + 700).toBeLessThanOrEqual(VW - 8);
      expect(p.top + 500).toBeLessThanOrEqual(VH - 8);
    }
  });
});
