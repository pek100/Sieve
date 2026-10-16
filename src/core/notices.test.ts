import { describe, expect, it } from "vitest";
import { createNoticeBus } from "./notices";

describe("notice bus (seam law: one queue, ids unique, dismiss removes)", () => {
  it("queues notices with unique ids, defaulting to toasts", () => {
    const bus = createNoticeBus();
    const a = bus.push({ kind: "info", text: "Paused until 10:15" });
    const b = bus.push({ kind: "success", text: "Removed", action: { label: "Undo", run: () => {} } });
    expect(a).not.toBe(b);
    expect(bus.list().map((n) => n.surface)).toEqual(["toast", "toast"]);
  });

  it("dismiss removes and notifies once", () => {
    const bus = createNoticeBus();
    let n = 0;
    bus.subscribe(() => n++);
    const id = bus.push({ kind: "error", text: "x", surface: "banner" });
    bus.dismiss(id);
    bus.dismiss(id);
    expect(bus.list()).toEqual([]);
    expect(n).toBe(2);
  });
});
