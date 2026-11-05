/**
 * Mock filter lists: the wire fixture's examples, through the same normaliser as
 * the Tauri answer. Query string `?lists=<scenario>`, default `pending`, which is
 * the truth today. The browser has no parser, so only the TS rule layer runs.
 */
import fixture from "./fixtures/filter-lists-v1.json";
import type { FilterListSource } from "./filter-lists-source";
import { parseFilterCatalogue } from "./protocol";

export const FILTER_LIST_SCENARIOS = ["pending", "loaded", "empty", "error"] as const;
export type FilterListScenario = (typeof FILTER_LIST_SCENARIOS)[number];

export const MOCK_LISTS_ERROR = "The filter list catalogue could not be read.";

export function createMockFilterLists(scenario: FilterListScenario = "pending"): FilterListSource {
  return {
    kind: "mock",
    catalogue: async () => {
      if (scenario === "error") throw new Error(MOCK_LISTS_ERROR);
      return parseFilterCatalogue(fixture.examples[scenario]);
    },
    checkRules: async () => [],
  };
}
