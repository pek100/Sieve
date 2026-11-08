/**
 * What a log row offers, and the pure reducers its actions write settings
 * through (plan 8.3). A rule is shown before anything is written; whether the
 * engine has it in force is the engine's to say, so nothing here claims it.
 */
import type { LogRow } from "@/data/protocol";
import { isAddressHost, rowUrl, urlFormHost } from "./log";
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

/**
 * The one reason a block rule would change what the row shows. An exception
 * rule outranks a plain block rule, and an app that is off is not filtered at
 * all; a reason this build does not know promises nothing either.
 */
const BLOCK_WOULD_APPLY = "no_rule";

/** Which actions apply to a row, in menu order. */
export function rowActions(row: Pick<LogRow, "url" | "kind" | "host" | "remote" | "outcome" | "rule">): LogAction[] {
  const outcome = row.outcome;
  const kind = outcome?.kind;
  const host = row.host ?? "";
  // The engine matches rules against a flow's decoded name, and an HTTP Host that
  // is an address is one (flow/http.rs), so a rule can name an address. Block needs
  // no more: only a decoded name reports `no_rule`. A row known by its address may
  // instead be closed for its names (every name it resolved to is blocked), and
  // an exception for the address would change nothing there, so Unblock asks that
  // the deciding rule names the address.
  const unblockable = !isAddressHost(host) || row.rule?.includes(urlFormHost(host)) === true;
  const applies: Record<LogAction, boolean> = {
    copy_url: rowUrl(row) !== null,
    unblock: host !== "" && unblockable && kind === "blocked" && row.rule !== null,
    block: host !== "" && kind === "passed" && outcome?.reason === BLOCK_WOULD_APPLY,
    // A problem row offers it only when decrypting was the problem; a retry is no decision at all.
    do_not_decrypt: kind === "problem" ? outcome.signal === "app_refused_certificate" : kind !== "not_decrypted" && kind !== "retried",
    report: true,
  };
  return LOG_ACTIONS.filter((a) => applies[a]);
}

/** A user rule that lets this host through. */
export const unblockRule = (host: string) => `@@||${urlFormHost(host)}^`;
/** A user rule that blocks this host. */
export const blockRule = (host: string) => `||${urlFormHost(host)}^`;

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
  /** Said instead when the line was there before: nothing is written. */
  already: string;
}

const inRules = (line: string) => ({ added: `Added ${line} to your rules.`, already: `${line} is already in your rules.` });

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
        ...inRules(line),
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
        ...inRules(line),
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
        already: `${host} is already in the sites not decrypted.`,
      };
  }
}
