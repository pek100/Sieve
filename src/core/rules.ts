/**
 * User rules and allowlist entries, the pure part: the friendly words. The
 * authority on rule syntax is the engine's parser (src-tauri/src/filters.rs,
 * `rule_check`); this layer knows no list of `$` options, which would rot. It
 * catches what a person gets wrong and says so in a sentence, and it refuses a
 * `trusted-` scriptlet whatever the parser says, because user rules are never
 * trusted. src/data/fixtures/user-rules-v1.json records both layers' answers.
 */

/** The most lines one rule text may hold, and the longest line. */
export const MAX_RULE_LINES = 5000;
export const MAX_RULE_CHARS = 4096;
/** What DNS allows of a name and of one label. */
export const MAX_HOST_CHARS = 253;
export const MAX_LABEL_CHARS = 63;

export type RuleCheck =
  | { kind: "blank" | "comment" | "ok" }
  /** A valid line that may not do what was meant. Does not stop a save. */
  | { kind: "hint"; message: string }
  /** Stops a save. */
  | { kind: "error"; message: string };

export interface RuleTextLine {
  /** Counts from 1. */
  n: number;
  line: string;
  check: RuleCheck;
}

export interface RuleText {
  lines: RuleTextLine[];
  /** Lines with an error or a hint. */
  notes: RuleTextLine[];
  /** A problem with the text as a whole (too many lines). */
  tooLong: string | null;
  /** False while any line has an error or the text is too long. */
  canSave: boolean;
  /** Blank lines dropped, comments kept: what is stored. */
  stored: string[];
}

/** Lines the parser reads as comments (is_comment in engine/crates/sieve-filter/src/rules.rs). */
const isComment = (l: string) => l.startsWith("!") || l.startsWith("[Adblock") || /^#\s/.test(l);
/** A cosmetic rule's separator; such a rule may hold spaces in its selector. */
const COSMETIC = /#[@?$%]*#/;
const SCRIPTLET = /#@?#\+js\(/;
const TRUSTED_SCRIPTLET = /#@?#\+js\(\s*trusted-/;
const NO_TARGET = /^(@@)?\|\|\^?(\$.*)?$/;

/** What ends a line. The parser reads a text by lines, so a line break inside one stored rule is a second rule. */
const LINE_BREAK = /\r\n|\r|\n/;

export function checkRuleLine(raw: string): RuleCheck {
  // First, on the raw text: a comment's mark or a cosmetic separator must not vouch for what follows a break.
  if (LINE_BREAK.test(raw)) return { kind: "error", message: "One rule fits on one line, and this one holds a line break." };
  const line = raw.trim();
  if (line === "") return { kind: "blank" };
  if (isComment(line)) return { kind: "comment" };
  if (line.length > MAX_RULE_CHARS) return { kind: "error", message: `This line is longer than ${MAX_RULE_CHARS} characters.` };
  if (TRUSTED_SCRIPTLET.test(line)) {
    return { kind: "error", message: "A trusted scriptlet can run anything on a page, so only the lists that write them may use one." };
  }
  if (SCRIPTLET.test(line)) {
    return line.endsWith(")") ? { kind: "ok" } : { kind: "error", message: "This scriptlet is not closed: it needs a ) at the end." };
  }
  if (COSMETIC.test(line)) return { kind: "ok" };
  if (/\s/.test(line)) return { kind: "error", message: "A network rule cannot hold a space." };
  if (NO_TARGET.test(line)) return { kind: "error", message: "This rule names no site. Write it as ||example.com^." };
  const host = normalizeDomain(line);
  if (host.ok && host.host === line.toLowerCase()) return { kind: "hint", message: `Did you mean ||${host.host}^?` };
  return { kind: "ok" };
}

export function checkRuleText(text: string): RuleText {
  const raw = text.split(LINE_BREAK);
  const lines = raw.map((line, i) => ({ n: i + 1, line, check: checkRuleLine(line) }));
  const notes = lines.filter((l) => l.check.kind === "error" || l.check.kind === "hint");
  const stored = lines.filter((l) => l.check.kind !== "blank").map((l) => l.line.trim());
  const tooLong = stored.length > MAX_RULE_LINES ? `This is more than ${MAX_RULE_LINES} rules.` : null;
  return { lines, notes, tooLong, canSave: tooLong === null && notes.every((l) => l.check.kind !== "error"), stored };
}

/**
 * The parser's words as a sentence (adblock-rust's error texts, read from its
 * source at 0.13.3). The raw reason stays beside it, so a word this does not
 * know still says something true.
 */
const REASONS: readonly (readonly [RegExp, string])[] = [
  [/unrecognised option/, "This rule has a $ option Sieve does not know."],
  [/generic script inject/, "A scriptlet must name the site it runs on, as example.com##+js(...)."],
  [/generic unhide/, "An exception must name the site it applies to."],
  [/invalid css selector/, "This CSS selector could not be read."],
  [/invalid css style/, "This CSS style could not be read."],
  [/scriptlet args/, "This scriptlet's arguments could not be read."],
  [/regex/, "This regular expression cannot be used."],
  [/punycode/, "This site name could not be read."],
  [/unsupported/, "Sieve does not support this kind of rule."],
  [/failed to parse filter|empty/, "This line could not be read as a rule."],
];

export function friendlyRuleReason(reason: string): string {
  return REASONS.find(([re]) => re.test(reason))?.[1] ?? "This line could not be read as a rule.";
}

export type DomainResult = { ok: true; host: string } | { ok: false; error: string };

const fail = (error: string): DomainResult => ({ ok: false, error });

/**
 * A host name from what a person typed or pasted: the host of a URL, lower case,
 * no trailing dot. At most 253 characters, two or more labels of a-z0-9-, no
 * leading or trailing hyphen, a non-numeric top label: stricter than the engine's
 * `domain_rule`, which takes what this gives (fixture `user-rules-v1.json`). One
 * sentence per failure.
 */
export function normalizeDomain(raw: string): DomainResult {
  const typed = raw.trim();
  if (typed === "") return fail("Type a site name, such as example.com.");
  if (/\s/.test(typed)) return fail("A site name cannot hold a space.");
  const host = typed
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
    .replace(/[/?#].*$/, "")
    .replace(/^.*@/, "")
    .replace(/:\d+$/, "")
    .replace(/\.+$/, "")
    .toLowerCase();
  if (host.length > MAX_HOST_CHARS) return fail(`A site name can have at most ${MAX_HOST_CHARS} characters.`);
  const labels = host.split(".");
  const labelOk = (l: string) => l.length >= 1 && l.length <= MAX_LABEL_CHARS && /^[a-z0-9-]+$/.test(l) && !l.startsWith("-") && !l.endsWith("-");
  if (!labels.every(labelOk)) return fail("A site name has only letters, digits, hyphens and dots, as in example.com.");
  if (labels.length < 2) return fail("A site name needs a dot, as in example.com. Names like localhost are not on the internet.");
  if (/^\d+$/.test(labels[labels.length - 1])) return fail("This is an IP address. Lists here take site names.");
  return { ok: true, host };
}

/**
 * The rule an allowlist entry stands for: connections to the host and its
 * subdomains pass an ordinary block from any list or user rule. It is not a
 * master switch. adblock-rust skips every exception, `$important` ones too, once
 * an `$important` block matches, and it says nothing about what the host's pages
 * load from elsewhere. The fixture's `allowlist` table, read by Rust
 * `filters::tests` with a real RuleEngine, holds this.
 */
export const allowRule = (host: string) => `@@||${host}^`;
/** What the allowlist does, in the words of `allowRule` above. */
export const ALLOWLIST_TEXT =
  "Connections to these sites go through even when a list or rule would block them, unless that rule is marked $important. What their pages load from other sites is still filtered.";
/** The rule "Block a site" writes. */
export const blockRule = (host: string) => `||${host}^`;

/** The one-rule form: a site, block or allow, its subdomains or not, a note. */
export interface RuleForm {
  host: string;
  action: "block" | "allow";
  subdomains: boolean;
  comment: string;
}

/**
 * The lines the form stands for: an optional `!` note, then the rule. With
 * subdomains, `||host^` (the host and every name under it); without, one
 * left-anchored rule per scheme, which a subdomain's address cannot start with.
 * An allow rule is the same with `@@`. The fixture's `form` table, read by Rust
 * `filters::tests` with a real RuleEngine, holds what each one decides.
 */
export function formRules(form: RuleForm): string[] {
  const mark = form.action === "allow" ? "@@" : "";
  const rules = form.subdomains ? [`${mark}||${form.host}^`] : ["https", "http"].map((scheme) => `${mark}|${scheme}://${form.host}^`);
  const note = form.comment.replace(/\s+/g, " ").trim();
  return note === "" ? rules : [`! ${note}`, ...rules];
}

/** The text with the form's lines added at its end, a rule already there not twice. */
export function withFormRules(text: string, form: RuleForm): string {
  const have = new Set(text.split(/\r?\n/).map((l) => l.trim()));
  const added = formRules(form).filter((l) => l.startsWith("!") || !have.has(l));
  if (added.every((l) => l.startsWith("!"))) return text;
  return text.trim() === "" ? added.join("\n") : `${text.replace(/\s+$/, "")}\n${added.join("\n")}`;
}
