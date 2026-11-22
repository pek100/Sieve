import type { Page } from "@playwright/test";

/**
 * An install from before 2026-11-22 with nothing set: its settings document is at
 * schema 5, so routing, HTTPS and page filtering read off (settings migration 5 -> 6).
 * A spec that means "the switches as an existing install has them" starts here; an
 * empty localStorage is a new install, whose switches are on. Written only while
 * nothing is stored, so a reload keeps what the page saved.
 */
export const asOldInstall = (page: Page) =>
  page.addInitScript(() => {
    if (window.localStorage.getItem("sieve.settings") === null) window.localStorage.setItem("sieve.settings", JSON.stringify({ schema: 5, values: {} }));
  });
