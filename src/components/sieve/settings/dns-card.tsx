"use client";

import { AlertTriangle, Plus, ShieldCheck, ShieldOff, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  blockRate,
  checkDetails,
  checkFailedLine,
  dnsPhase,
  DNS_SWITCH,
  isUpstream,
  STRANDED_DNS_TEXT,
  strandedAdapters,
  UPSTREAMS_KEY,
  type DnsPhase,
  type DnsSlice,
} from "@/core/dns";
import type { SettingKey } from "@/core/settings/registry";
import type { SelfCheck } from "@/data/protocol";
import { useDns, useSetting } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";
import type { Lock } from "./use-settings-view";

/**
 * Settings this card edits in place (the upstream list). The Settings screen
 * gives them no row of their own, so each one has a single owner on screen.
 */
export const DNS_CARD_KEYS: ReadonlySet<SettingKey> = new Set<SettingKey>([UPSTREAMS_KEY]);

/** How many blocked domains the card lists (Rust keeps 20). */
const TOP_SHOWN = 10;

const count = (n: number) => n.toLocaleString();
const when = (ms: number) => new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

/** The status line, in words, by phase. */
function statusLine(phase: DnsPhase, d: DnsSlice): string {
  switch (phase) {
    case "off":
      return "Off. Lookups go to Windows' own DNS servers.";
    case "starting":
      return "Starting the filter...";
    case "checking":
      return "Running its self check...";
    case "stopping":
      return "Stopping...";
    case "running":
      return `Running on ${(d.status?.binds ?? []).join(" and ")}.`;
    case "paused":
      return "Paused while Sieving is off: lookups pass through to the upstream servers, nothing is blocked.";
    case "error":
      return "Off: the last attempt failed.";
  }
}

/** One short line; a failure's technical replies are in `CheckDetails`. */
function checkLine(c: SelfCheck): string {
  if (c.pass) {
    const servers = [...new Set((c.checks ?? []).filter((x) => x.kind === "canary").map((x) => x.server))];
    return `Self check passed: the test name is blocked on ${servers.join(" and ")}, and a normal name resolves.`;
  }
  return checkFailedLine(c);
}

/** The failed checks' replies as the filter gave them, folded away, each line once. */
function CheckDetails({ c }: { c: SelfCheck }) {
  const lines = checkDetails(c);
  if (lines.length === 0) return null;
  return (
    <details className="text-label text-on-surface-muted" data-dns-check-details="">
      <summary className="cursor-pointer select-none">Self check details</summary>
      <ul className="mt-2 flex flex-col gap-1">
        {lines.map((line) => (
          <li key={line} className="font-mono text-mono break-all text-on-surface">
            {line}
          </li>
        ))}
      </ul>
    </details>
  );
}

function Note({ tone, children, label }: { tone: "warning" | "error" | "info"; children: ReactNode; label?: string }) {
  return (
    <div
      role={tone === "error" ? "alert" : "note"}
      aria-label={label}
      className="flex items-start gap-3 text-label"
    >
      <AlertTriangle
        aria-hidden="true"
        className={cn("size-4 shrink-0", tone === "error" ? "text-blocked" : tone === "warning" ? "text-warning" : "text-info")}
        strokeWidth={1.75}
      />
      <div className="min-w-0 break-words text-on-surface">{children}</div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section aria-label={title} className="flex flex-col gap-2">
      <h3 className="text-body-strong text-on-surface">{title}</h3>
      {children}
    </section>
  );
}

function Stat({ label, value, id }: { label: string; value: string; id: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1" data-stat={id}>
      <dt className="text-label text-on-surface-muted">{label}</dt>
      <dd className="text-title tabular" data-numeric="">
        {value}
      </dd>
    </div>
  );
}

/** Upstream servers, edited in place; the setting is the list handed to dns_start. */
function Upstreams({ inUse }: { inUse: string[] | null }) {
  const [list, setList] = useSetting(UPSTREAMS_KEY);
  const [draft, setDraft] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const add = () => {
    const v = draft.trim();
    if (!isUpstream(v)) {
      setProblem(`"${v}" is not an IP address. Use an address such as 1.1.1.1 or 2606:4700::1111, with a port if it is not 53.`);
      return;
    }
    if (list.includes(v)) {
      setProblem(`${v} is already in the list.`);
      return;
    }
    setProblem(null);
    setDraft("");
    void setList([...list, v]);
  };
  return (
    <Section title="Upstream DNS servers">
      <p className="text-label text-on-surface-muted">
        Lookups the filter does not block go to these, in order. A change applies the next time DNS filtering starts.
      </p>
      <ul aria-label="Upstream servers" className="flex flex-wrap gap-2">
        {list.map((u) => (
          <li key={u} className="flex items-center gap-1">
            <span className="font-mono text-mono">{u}</span>
            <IconButton label={`Remove ${u}`} disabled={list.length <= 1} onClick={() => void setList(list.filter((x) => x !== u))}>
              <X strokeWidth={1.75} />
            </IconButton>
          </li>
        ))}
      </ul>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          add();
        }}
      >
        <Input
          aria-label="Add an upstream server"
          aria-invalid={problem !== null || undefined}
          placeholder="9.9.9.9"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="h-9 max-w-60 flex-1 rounded-full bg-inset px-3 font-mono text-mono"
        />
        <Button type="submit" variant="secondary" disabled={draft.trim() === ""}>
          <Plus strokeWidth={1.75} />
          Add
        </Button>
      </form>
      {problem && (
        <p role="alert" className="text-label text-blocked">
          {problem}
        </p>
      )}
      {inUse && (
        <p className="text-label text-on-surface-muted">
          In use now: <span className="font-mono text-mono break-all text-on-surface">{inUse.join(", ")}</span>
        </p>
      )}
    </Section>
  );
}

/**
 * Settings > Filtering, the DNS filter: its switch, what it is doing, its
 * counters and list, the most blocked domains and the upstreams. Every
 * value comes from the store's `dns` part; the switch is the setting the
 * DNS controller follows. Sieve never points Windows DNS at the filter, so
 * the card says plainly what it covers (lookups sent to 127.0.0.1:53), and
 * the safety notice while an adapter still asks it and nothing answers.
 * The card never names an app.
 */
export function DnsCard({ lockOf }: { lockOf: (key: typeof DNS_SWITCH) => Lock | null }) {
  const d = useDns();
  const [on, setOn] = useSetting(DNS_SWITCH);
  const phase = dnsPhase(d);
  const running = d.status?.running === true;
  const stranded = strandedAdapters(d.windows ?? null, d.status ?? null).length > 0;
  const c = d.status?.counters;
  const rate = c ? blockRate(c) : null;
  const list = d.status?.list;
  const top = (d.status?.top_blocked ?? []).slice(0, TOP_SHOWN);
  const busy = d.busy !== null;

  return (
    <Card
      title="DNS filter"
      icon={running ? <ShieldCheck strokeWidth={1.75} /> : <ShieldOff strokeWidth={1.75} />}
      tone={running ? "mint" : "neutral"}
      action={
        <Switch
          aria-label="DNS filtering"
          checked={on}
          disabled={busy || lockOf(DNS_SWITCH) !== null}
          onCheckedChange={(v) => void setOn(v)}
        />
      }
    >
      <div className="flex flex-col gap-6" data-dns-card="" data-dns-phase={phase}>
        <div className="flex flex-col gap-1">
          <p className="text-body text-on-surface" data-dns-status="">
            {statusLine(phase, d)}
          </p>
          <p className="text-label text-on-surface-muted" data-dns-scope="">
            Only lookups sent straight to 127.0.0.1:53 are filtered for now; filtering for the whole computer comes later.
          </p>
        </div>

        {stranded && !busy && (
          <Note tone="error" label="Windows DNS">
            <span data-dns-stranded="">{STRANDED_DNS_TEXT}</span>
          </Note>
        )}

        {d.adguard && (
          <Note tone="warning" label="AdGuard is running">
            AdGuard is running. Its own DNS protection intercepts lookups before they reach Sieve. Pause AdGuard&apos;s DNS protection
            for Sieve&apos;s filter to be the one deciding.
          </Note>
        )}

        {/* A failed check's line is said once, by the check line below. */}
        {d.error && (phase === "error" || phase === "running") && d.error !== (d.check && checkLine(d.check)) && (
          <Note tone="error">{d.error}</Note>
        )}

        {d.check && (
          <div className="flex flex-col gap-2">
            <p
              role={d.check.pass ? undefined : "alert"}
              className={cn("text-label", d.check.pass ? "text-on-surface-muted" : "text-blocked")}
              data-dns-check={d.check.pass ? "pass" : "fail"}
            >
              {checkLine(d.check)}
            </p>
            {!d.check.pass && <CheckDetails c={d.check} />}
          </div>
        )}

        {running && c && (
          <dl aria-label="Since the filter started" className="grid grid-cols-3 gap-4">
            <Stat id="queries" label="Lookups" value={count(c.queries)} />
            <Stat id="blocked" label="Blocked" value={count(c.blocked)} />
            <Stat id="rate" label="Block rate" value={rate === null ? "None yet" : `${(rate * 100).toFixed(1)}%`} />
          </dl>
        )}

        {running && list && (
          <Section title="Filter list">
            <p className="text-label text-on-surface-muted" data-dns-list="">
              {list.fetched_at === null
                ? "No list is loaded, so nothing is blocked."
                : `${count(list.rules)} block rules, ${count(list.allow)} allow rules, ${count(list.skipped)} lines skipped. Updated ${when(list.fetched_at)}.`}
              {list.user_rules && " Your own rules are in force."}
            </p>
            {list.url && <p className="font-mono text-mono break-all text-on-surface-muted">{list.url}</p>}
            {list.error && <Note tone="warning">The list could not be refreshed: {list.error}</Note>}
          </Section>
        )}

        {running && (
          <Section title="Most blocked domains">
            {top.length === 0 ? (
              <p className="text-label text-on-surface-muted">Nothing blocked yet.</p>
            ) : (
              <ol aria-label="Most blocked domains" className="flex flex-col">
                {top.map((t) => (
                  <li key={t.domain} className="flex h-9 items-center justify-between gap-3">
                    <span className="min-w-0 truncate font-mono text-mono">{t.domain}</span>
                    <span className="text-label text-on-surface-muted tabular">{count(t.count)}</span>
                  </li>
                ))}
              </ol>
            )}
          </Section>
        )}

        <Upstreams inUse={running ? (d.status?.upstreams ?? null) : null} />
      </div>
    </Card>
  );
}
