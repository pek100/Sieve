/**
 * The filter list seam: the catalogue and its per-list counts, and the parser's
 * verdict on user rules. `tauri` calls the Rust commands (src-tauri/src/filters.rs),
 * `mock` (filter-lists-mock.ts) answers from the fixture. Engine slice 4 feeds
 * the reports; until then every report is null, which reads "Not loaded yet".
 */
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseFilterCatalogue, parseRuleProblems, type FilterCatalogue, type RuleProblem } from "./protocol";

export interface FilterListSource {
  readonly kind: "mock" | "tauri";
  /** Rejects when it cannot be read or its shape is unknown. */
  catalogue(): Promise<FilterCatalogue>;
  /** What the engine's parser refuses in these lines. */
  checkRules(lines: readonly string[]): Promise<RuleProblem[]>;
}

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

export function createTauriFilterLists(invoke: Invoke = tauriInvoke): FilterListSource {
  return {
    kind: "tauri",
    catalogue: async () => parseFilterCatalogue(await invoke<unknown>("filter_catalogue")),
    checkRules: async (lines) => parseRuleProblems(await invoke<unknown>("rule_check", { lines })),
  };
}
