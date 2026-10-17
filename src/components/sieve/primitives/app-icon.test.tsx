import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import type { SieveSource } from "@/data/source";
import { createRuntime } from "@/hooks/runtime";
import { SieveProvider } from "@/hooks/sieve-provider";
import { AppIcon } from "./app-icon";

const EXE = "C:\\Program Files\\Example\\example.exe";

function mount(source: SieveSource, exe: string | null) {
  const runtime = createRuntime({ source, settings: memoryBackend() });
  return render(
    <SieveProvider runtime={runtime}>
      <AppIcon exe={exe}>
        <span>EX</span>
      </AppIcon>
    </SieveProvider>,
  );
}

const box = (c: HTMLElement) => c.querySelector<HTMLElement>("[data-app-icon]")!;

describe("AppIcon", () => {
  it("shows the monogram while loading, then the exe's own icon, in the same fixed box with no tile", async () => {
    const { container } = mount(createMockSource({ seed: 1, icons: true }), EXE);
    expect(box(container)).toHaveAttribute("data-app-icon", "fallback");
    expect(screen.getByText("EX")).toBeInTheDocument();
    const before = box(container).className;
    await expect.poll(() => box(container).getAttribute("data-app-icon")).toBe("image");
    const el = container.querySelector("img")!;
    expect(el.getAttribute("src")).toMatch(/^data:image\/png;base64,iVBORw0KGgo/);
    expect(el.getAttribute("srcset")).toMatch(/ 1x, data:image\/png;base64,.+ 2x$/);
    // Same box before and after: nothing moves when the icon arrives; no tile behind it.
    expect(box(container).className).toBe(before);
    expect(box(container).className).toContain("size-8");
    expect(box(container).className).not.toMatch(/\bbg-|rounded/);
    expect(screen.queryByText("EX")).toBeNull();
  });

  it("keeps the monogram when there is no icon, no exe, or the request fails", async () => {
    const plain = mount(createMockSource({ seed: 1 }), EXE);
    await new Promise((r) => setTimeout(r, 10));
    expect(box(plain.container)).toHaveAttribute("data-app-icon", "fallback");
    plain.unmount();

    const none = mount(createMockSource({ seed: 1, icons: true }), null);
    expect(box(none.container)).toHaveAttribute("data-app-icon", "fallback");
    none.unmount();

    const failing: SieveSource = { ...createMockSource({ seed: 1 }), appIcon: () => Promise.reject(new Error("shell refused")) };
    const failed = mount(failing, EXE);
    await new Promise((r) => setTimeout(r, 10));
    expect(box(failed.container)).toHaveAttribute("data-app-icon", "fallback");
    expect(screen.getByText("EX")).toBeInTheDocument();
  });
});
