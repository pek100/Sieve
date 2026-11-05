/**
 * What a log row offers, and the pure reducers its actions write settings
 * through (plan 8.3). A rule is shown before anything is written; whether the
 * engine has it in force is the engine's to say, so nothing here claims it.
 */
import type { LogRow } from "@/data/protocol";
import { rowUrl } from "./log";
import type { SettingKey } from "./settings/registry";

export const LOG_ACTIONS = ["copy_url", "unblock", "block", "do_not_decrypt", "report"] as const;
export type LogAction = (typeof LOG_ACTIONS)[number];

export const LOG_ACTION_TEXT: Record<LogAction, string> = {
  copy_url: "Copy URL",
  unblock: "Unblock",
  block: "Block",
  do_not_decrypt: "Do not decrypt this site",
  report: "Report a broken site",
};

/** Which actions apply to a row, in menu order. */
export function rowActions(row: Pick<LogRow, "url" | "kind" | "host" | "outcome" | "rule">): LogAction[] {
  const kind = row.outcome?.kind;
  const applies: Record<LogAction, boolean> = {
    copy_url: rowUrl(row) !== null,
    unblock: kind === "blocked" && row.rule !== null,
    block: kind === "passed",
    do_not_decrypt: kind !== "not_decrypted",
    report: true,
  };
  return LOG_ACTIONS.filter((a) => applies[a]);
}

/** A user rule that lets this host through. */
export const unblockRule = (host: string) => `@@||${host}^`;
/** A user rule that blocks this host. */
export const blockRule = (host: string) => `||${host}^`;

/** The list with `line` at its end, once. */
export function addLine(list: readonly string[], line: string): readonly string[] {
  return list.includes(line) ? list : [...list, line];
}

export function removeLine(list: readonly string[], line: string): readonly string[] {
  return list.filter((l) => l !== line);
}

export type PreviewAction = Extract<LogAction, "unblock" | "block" | "do_not_decrypt">;

export interface LinePreview {
  action: PreviewAction;
  /** The setting that takes the line. */
  key: Extract<SettingKey, "filtering.userRules" | "filtering.exclusions">;
  /** Exactly what is written. */
  line: string;
  title: string;
  body: string;
  /** Said after it is written: that it was added, not that it is in force. */
  added: string;
}

/** What an action would write for a host, before anything is written. */
export function previewOf(action: PreviewAction, host: string): LinePreview {
  switch (action) {
    case "unblock": {
      const line = unblockRule(host);
      return {
        action,
        key: "filtering.userRules",
        line,
        title: `Unblock ${host}`,
        body: "This exception rule goes in your rules. It lets this host and its subdomains through.",
        added: `Added ${line} to your rules.`,
      };
    }
    case "block": {
      const line = blockRule(host);
      return {
        action,
        key: "filtering.userRules",
        line,
        title: `Block ${host}`,
        body: "This rule goes in your rules. It blocks this host and its subdomains.",
        added: `Added ${line} to your rules.`,
      };
    }
    case "do_not_decrypt":
      return {
        action,
        key: "filtering.exclusions",
        line: host,
        title: `Do not decrypt ${host}`,
        body: "This goes in the sites Sieve leaves encrypted, with its subdomains.",
        added: `Added ${host} to the sites not decrypted.`,
      };
  }
}
