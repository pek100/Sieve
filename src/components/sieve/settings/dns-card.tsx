"use client";

import { AlertTriangle, Plus, ShieldCheck, ShieldOff, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { blockRate, dnsPhase, DNS_SWITCH, isUpstream, SYSTEM_DNS_SWITCH, UPSTREAMS_KEY, type DnsPhase, type DnsSlice } from "@/core/dns";
import type { SettingKey } from "@/core/settings/registry";
import type { FamilyDns, InterfaceDns, SelfCheck } from "@/data/protocol";
import { useCheckPassed, useDns, useDnsActions, useSetting } from "@/hooks/use-sieve";
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

function checkLine(c: SelfCheck): string {
  if (c.pass) {
    const servers = [...new Set(c.checks.filter((x) => x.kind === "canary").map((x) => x.server))];
    return `Self check passed: the test name is blocked on ${servers.join(" and ")}, and a normal name resolves.`;
  }
  return `Self check failed: ${c.checks
    .filter((x) => !x.pass)
    .map((x) => `${x.name || "blocked name"} on ${x.server || "the filter"} got ${x.got}`)
    .join("; ")}.`;
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

function familyText(f: FamilyDns): string {
  if (f.servers.length === 0) return f.dhcp ? "none (DHCP)" : "none";
  return `${f.servers.join(", ")} (${f.dhcp ? "DHCP" : "set by hand"})`;
}

function AdapterRow({ it }: { it: InterfaceDns & { uses_sieve: boolean } }) {
  return (
    <li className="flex min-w-0 flex-col gap-1" data-adapter={it.alias}>
      <p className="flex flex-wrap items-center gap-2 text-body-strong">
        {it.alias}
        {it.uses_sieve && <span className="text-caption text-primary">Uses Sieve</span>}
      </p>
      <p className="text-label text-on-surface-muted">
        IPv4 <span className="font-mono text-mono break-all text-on-surface">{familyText(it.v4)}</span>
      </p>
      <p className="text-label text-on-surface-muted">
        IPv6 <span className="font-mono text-mono break-all text-on-surface">{familyText(it.v6)}</span>
      </p>
    </li>
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
 * counters and list, the most blocked domains, upstreams, and Windows DNS
 * with the one system change Sieve makes (point and restore). Every value
 * comes from the store's `dns` part; actions go to the DNS controller.
 * Blocking is for the whole computer: the card never names an app.
 */
export function DnsCard({ lockOf }: { lockOf: (key: typeof DNS_SWITCH | typeof SYSTEM_DNS_SWITCH) => Lock | null }) {
  const d = useDns();
  const actions = useDnsActions();
  const passed = useCheckPassed();
  const [on, setOn] = useSetting(DNS_SWITCH);
  const phase = dnsPhase(d);
  const running = d.status?.running === true;
  const system = d.system;
  const pointed = system?.pointed === true;
  const c = d.status?.counters;
  const rate = c ? blockRate(c) : null;
  const list = d.status?.list;
  const top = (d.status?.top_blocked ?? []).slice(0, TOP_SHOWN);
  const busy = d.busy !== null;
  const canPoint = running && passed(DNS_SWITCH) && system !== null && !pointed && !busy && lockOf(SYSTEM_DNS_SWITCH) === null;
  const canRestore = (pointed || system?.backup === true) && !busy;

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
          <p className="text-label text-on-surface-muted">
            Filters every app on this computer at once: Windows sends all lookups through one service, so a DNS filter cannot tell
            apps apart.
          </p>
        </div>

        {d.adguard && (
          <Note tone="warning" label="AdGuard is running">
            AdGuard is running. Its own DNS protection intercepts lookups before they reach Sieve. Pause AdGuard&apos;s DNS protection
            for Sieve&apos;s filter to be the one deciding.
          </Note>
        )}

        {d.error && (phase === "error" || phase === "running") && <Note tone="error">{d.error}</Note>}

        {running && system !== null && !pointed && (
          <Note tone="info">Windows does not use Sieve for DNS yet, so nothing is blocked. Point Windows at Sieve below.</Note>
        )}

        {d.check && (
          <p className={cn("text-label", d.check.pass ? "text-on-surface-muted" : "text-blocked")} data-dns-check={d.check.pass ? "pass" : "fail"}>
            {checkLine(d.check)}
          </p>
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

        <Section title="Windows DNS">
          <p className="text-label text-on-surface-muted" data-system-dns={system === null ? "unknown" : pointed ? "pointed" : "own"}>
            {system === null
              ? "Reading Windows DNS..."
              : pointed
                ? "Windows uses Sieve for DNS (127.0.0.1 and ::1)."
                : "Windows uses its own DNS servers. Pointing it at Sieve saves a backup first; Windows asks for administrator rights."}
          </p>
          {system !== null && system.interfaces.length > 0 && (
            <ul aria-label="Network adapters" className="flex flex-col gap-3">
              {system.interfaces.map((it) => (
                <AdapterRow key={`${it.index}-${it.alias}`} it={it} />
              ))}
            </ul>
          )}
          <div className="flex flex-wrap gap-2">
            <Button disabled={!canPoint} onClick={() => void actions.point()}>
              Point Windows at Sieve
            </Button>
            <Button variant="secondary" disabled={!canRestore} onClick={() => void actions.restore()}>
              Restore my DNS
            </Button>
          </div>
          {!running && !pointed && <p className="text-label text-on-surface-muted">Turn DNS filtering on first; its self check must pass.</p>}
          {system?.backup && system.backup_dir && (
            <p className="text-label text-on-surface-muted">
              Backup and <span className="font-mono text-mono">restore-dns.ps1</span> (works without Sieve):{" "}
              <span className="font-mono text-mono break-all text-on-surface">{system.backup_dir}</span>
            </p>
          )}
        </Section>
      </div>
    </Card>
  );
}
