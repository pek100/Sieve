/**
 * Each app's recent problems, the pure part: what they say in words, who most
 * likely caused them, what one step fixes them, and when the user is told. The
 * cause of each problem is the engine's (`sieve_ipc::Signal::cause`, the one
 * table), carried on the wire; nothing here classifies a signal again. All of it
 * stays on this PC: nothing here or behind it sends anything anywhere.
 */
import type { AppIssues, Cause, Problem, Signal } from "@/data/protocol";
import { exclusionLine, type ExclusionView } from "./exclusions";
import { previewOf, type LinePreview } from "./log-actions";

/** What happened, said as a person would. Held to sieve-ipc's `Signal` by law 9. */
export const SIGNAL_TEXT: Readonly<Record<Signal, string>> = {
  connect_refused: "The server turned the connection away",
  connect_timeout: "The server did not answer",
  unreachable: "The network could not reach the server",
  connect_failed: "The connection could not be made",
  egress_failed: "Sieve found no way out to the internet for it",
  connection_lost: "The connection broke off",
  stall: "It waited for an answer that never came",
  dns_unanswered: "Looking up a site's address got no answer",
  app_refused_certificate: "It refused to let Sieve look inside its secure connection",
  blocked: "Sieve blocked it with a filter rule",
  quic_refused: "Sieve asked it to use a regular connection, so it can be filtered",
};

/** Sieve meant these: a rule's block, a QUIC refusal the app answers by falling back. The engine's `Signal::intended`. */
const INTENDED: ReadonlySet<Signal> = new Set(["blocked", "quic_refused"]);
export const isIntended = (p: Pick<Problem, "signal">) => INTENDED.has(p.signal);

export const CAUSE_TEXT: Readonly<Record<Cause, string>> = {
  sieve: "Likely Sieve",
  network: "Likely the network or the server, not Sieve",
  unknown: "Sieve cannot tell",
};

/** One app's likely cause, from its problems: Sieve if any failure was Sieve's, else unknown, else the network. */
export type Verdict = Cause | "intended";

export const VERDICT_TEXT: Readonly<Record<Verdict, string>> = {
  sieve: "Sieve is the likely cause.",
  unknown: "Sieve cannot tell whether it is the cause.",
  network: "The network or the server is the likely cause. The same would happen without Sieve.",
  intended: "Only connections a filter rule blocked.",
};

/** The problems the app felt: everything but what Sieve meant. */
export const failures = (app: Pick<AppIssues, "problems">): Problem[] => (app.problems ?? []).filter((p) => !isIntended(p));

const sum = (problems: readonly Problem[]) => problems.reduce((n, p) => n + (p.count ?? 0), 0);

export function verdict(app: Pick<AppIssues, "problems">): Verdict {
  const felt = failures(app);
  for (const cause of ["sieve", "unknown", "network"] as const) if (felt.some((p) => p.cause === cause)) return cause;
  return "intended";
}

/** Apps the user should look at: those with a failure, in the engine's order (newest problem first). */
export const troubled = (apps: readonly AppIssues[] | null | undefined): AppIssues[] => (apps ?? []).filter((a) => failures(a).length > 0);

/** An app's name as the Apps screen shows it (an app or a VM row by key), else its exe, else its key. */
export function issueName(app: Pick<AppIssues, "key" | "exe">, known: readonly { key: string; name: string }[]): string {
  return known.find((k) => k.key === app.key)?.name ?? app.exe ?? app.key;
}

/** The app's line under its name: how many connections had trouble, of how many. */
export function summaryText(app: AppIssues): string {
  const felt = sum(failures(app));
  const blocked = sum((app.problems ?? []).filter(isIntended));
  const of = app.flows > 0 ? ` of ${app.flows}` : "";
  const parts = [felt > 0 ? `${felt}${of} ${plural(felt, "connection")} had trouble` : null, blocked > 0 ? `${blocked} blocked by a filter rule` : null].filter(Boolean);
  return parts.join(", ");
}

const plural = (n: number, word: string) => (n === 1 ? word : `${word}s`);

/** A problem in words: what happened, with whom, how often. */
export function problemText(p: Problem): string {
  const times = p.count === 1 ? "once" : `${p.count} times`;
  return p.host ? `${SIGNAL_TEXT[p.signal]}: ${p.host}, ${times}` : `${SIGNAL_TEXT[p.signal]}, ${times}`;
}

/** A clock time for a problem's newest, in the user's own format. Null for no time. */
export function factTime(ms: number | null | undefined): string | null {
  if (typeof ms !== "number" || !Number.isFinite(ms) || ms <= 0) return null;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ---- When to tell the user.

/** Failures that make "it started failing right after Sieve began filtering it". */
export const NOTIFY_FAILURES = 3;
/** "Right after": the first of them this soon after Sieve first saw the app. */
export const NOTIFY_AFTER_START_MS = 10 * 60_000;

/**
 * True when the app started failing repeatedly right after Sieve began filtering
 * it, and Sieve may be why: failures the network alone explains never tell.
 */
export function startedFailing(app: AppIssues): boolean {
  const suspect = failures(app).filter((p) => p.cause !== "network");
  if (sum(suspect) < NOTIFY_FAILURES) return false;
  const first = Math.min(...suspect.map((p) => p.first_ms));
  return first - app.since_ms <= NOTIFY_AFTER_START_MS;
}

/** The notice's words. Plain, and it names the way out. */
export const startedFailingText = (name: string) => `${name} has been failing since Sieve started filtering it. Open Apps to see why and fix it in one step.`;

// ---- One-step fixes.

export const FIXES = ["unblock", "stop_decrypting", "keep_untouched", "try_again", "turn_off", "report"] as const;
export type Fix = (typeof FIXES)[number];

export const FIX_TEXT: Readonly<Record<Fix, string>> = {
  unblock: "Unblock this site",
  stop_decrypting: "Stop decrypting it for this app",
  keep_untouched: "Keep it this way",
  try_again: "Try decrypting again",
  turn_off: "Turn Sieve off for this app",
  report: "Copy a report",
};

/** What fixes one problem by itself; only where Sieve is the cause and a host is named. */
export function problemFixes(p: Problem, exe: string | null): Fix[] {
  if (!p.host) return [];
  if (p.signal === "blocked") return ["unblock"];
  if (p.signal === "app_refused_certificate" && exe) return ["stop_decrypting"];
  return [];
}

/** What the `auto:failing` row means, after its time. */
export const UNTOUCHED_TEXT = "Sieve passes this app through untouched for a day, because it kept refusing Sieve's certificate right after Sieve began decrypting it. Its blocked sites stay blocked.";

/** The `auto:failing` row of this app's exe: Sieve passes the whole app through untouched for now. */
export function failingOpen(rows: readonly ExclusionView[], exe: string | null): ExclusionView | null {
  if (!exe) return null;
  return rows.find((r) => r.reason === "auto:failing" && r.apps.includes(exe)) ?? null;
}

/** The whole app's fixes: Off and a report whenever Sieve may be the cause; keep or try again while it passes untouched. */
export function appFixes(app: AppIssues, untouched: ExclusionView | null, canTurnOff: boolean): Fix[] {
  const fixes: Fix[] = [];
  if (untouched) fixes.push("keep_untouched", "try_again");
  if (verdict(app) === "sieve" || verdict(app) === "unknown") {
    if (canTurnOff) fixes.push("turn_off");
    fixes.push("report");
  }
  return fixes;
}

/** The line a fix writes, shown before it is written (`rule-preview.tsx`). */
export function fixPreview(fix: Fix, host: string | null, exe: string | null): LinePreview | null {
  switch (fix) {
    case "unblock":
      return host ? previewOf("unblock", host) : null;
    case "stop_decrypting": {
      if (!host || !exe) return null;
      const line = exclusionLine(host, exe);
      return {
        action: "do_not_decrypt",
        key: "filtering.exclusions",
        line,
        title: `Stop decrypting ${host} for ${exe}`,
        body: "This goes in the sites Sieve leaves encrypted, for this app only, with its subdomains.",
        added: `Added ${line} to the sites not decrypted.`,
        already: `${line} is already in the sites not decrypted.`,
      };
    }
    case "keep_untouched": {
      if (!exe) return null;
      const line = exclusionLine("*", exe);
      return {
        action: "do_not_decrypt",
        key: "filtering.exclusions",
        line,
        title: `Never decrypt ${exe}`,
        body: "This goes in the sites Sieve leaves encrypted: every site, for this app only. Its blocked sites stay blocked.",
        added: `Added ${line} to the sites not decrypted.`,
        already: `${line} is already in the sites not decrypted.`,
      };
    }
    default:
      return null;
  }
}

/** What "Copy a report" puts on the clipboard: the app's problems in words, nothing else. Never sent. */
export function reportText(app: AppIssues, name: string, version: string | null): string {
  return [
    `Sieve ${version ?? "(version unknown)"}: ${name} (${app.exe ?? app.key})`,
    VERDICT_TEXT[verdict(app)],
    summaryText(app),
    ...(app.problems ?? []).map((p) => `- ${problemText(p)} (${CAUSE_TEXT[p.cause]})`),
    retriesText(app),
  ]
    .filter((l): l is string => l !== null && l !== "")
    .join("\n");
}

/** How Sieve's retries went, or null with none. */
export function retriesText(app: Pick<AppIssues, "retried" | "recovered">): string | null {
  if (!(app.retried > 0)) return null;
  return `Sieve tried ${app.retried} ${plural(app.retried, "connection")} again before the app noticed; ${app.recovered} then worked.`;
}
