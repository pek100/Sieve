import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ROUTES } from "@/core/routes";
import { createMockSource } from "@/data/mock-source";
import { memoryBackend } from "@/data/settings-store";
import { createRuntime } from "@/hooks/runtime";
import { AppShell } from "./app-shell";
import { Card } from "./card";

vi.mock("next/navigation", () => ({ usePathname: () => "/" }));

function setup() {
  const runtime = createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() });
  const view = render(
    <AppShell runtime={runtime}>
      <main>content</main>
    </AppShell>,
  );
  return { runtime, view };
}

describe("app shell (seam law: shell renders ROUTES and binds the master switch to sampling)", () => {
  it("renders the top bar with one nav link per route, Home current", () => {
    setup();
    const nav = screen.getByRole("navigation", { name: "Main" });
    const links = within(nav).getAllByRole("link");
    expect(links).toHaveLength(ROUTES.length);
    expect(links[0]).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("content")).toBeInTheDocument();
  });

  it("starts sampling once settings load, and the master switch stops it", async () => {
    const { runtime } = setup();
    await act(async () => {
      await runtime.settings.ready;
    });
    expect(runtime.store.getState().status.running).toBe(true);
    await userEvent.click(screen.getByRole("switch", { name: "Sieving" }));
    expect(runtime.settings.get("sampling.enabled")).toBe(false);
    expect(runtime.store.getState().status.running).toBe(false);
    expect(screen.getByRole("status")).toHaveAttribute("data-phase", "off");
  });

  it("gives every icon-only button an accessible name", () => {
    setup();
    for (const b of screen.getAllByRole("button")) expect(b).toHaveAccessibleName();
  });
});

describe("card", () => {
  it("shows loading, empty and error states, and contains a crash", () => {
    const Boom = () => {
      throw new Error("kaboom");
    };
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    render(
      <>
        <Card title="Loading" state={{ kind: "loading" }} />
        <Card title="Empty" state={{ kind: "empty", line: "Nothing is talking right now" }} />
        <Card title="Error" state={{ kind: "error", message: "Source failed" }} />
        <Card title="Crash">
          <Boom />
        </Card>
      </>,
    );
    expect(screen.getByRole("region", { name: "Loading" })).toHaveAttribute("aria-busy", "true");
    expect(screen.getByText("Nothing is talking right now")).toBeInTheDocument();
    expect(screen.getByText("Source failed")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Crash" })).getByRole("alert")).toHaveTextContent("kaboom");
    spy.mockRestore();
  });
});
