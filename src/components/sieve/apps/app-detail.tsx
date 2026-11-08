"use client";

import { Bug, Check, Copy, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ReportDialog } from "@/components/sieve/log/report-dialog";
import { CardBoundary } from "@/components/sieve/shell/card";
import { EmptyState } from "@/components/sieve/shell/empty-state";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { AppIcon } from "@/components/sieve/primitives/app-icon";
import { iconExe, isActiveFlow } from "@/core/apps";
import type { AppEntry } from "@/core/apps-actions";
import { issueName } from "@/core/issues";
import { canTurnOff } from "@/core/policy";
import type { Flow } from "@/data/protocol";
import { useEngine } from "@/hooks/use-sieve";
import { AppExclusionsLine } from "./app-exclusions-line";
import { AppProblems } from "./app-issues";
import { CATEGORY_LABEL, type RowActions } from "./app-list";
import { AppToggle, APP_OFF_MEANS } from "./app-toggle";
import { Monogram } from "./monogram";

const MAX_ROWS = 40;

const STATE_LABEL: Partial<Record<Flow["state"], string>> = {
  established: "Open",
  time_wait: "Closing",
  close_wait: "Closing",
  fin_wait_1: "Closing",
  fin_wait_2: "Closing",
  last_ack: "Closing",
  closing: "Closing",
  syn_sent: "Opening",
  syn_received: "Opening",
  listen: "Listening",
  none: "Bound",
};

function host(f: Flow): string {
  if (!f.remote) return `local :${f.local.port}`;
  return f.family === "v6" ? `[${f.remote.addr}]:${f.remote.port}` : `${f.remote.addr}:${f.remote.port}`;
}

/** Click to copy, with a checkmark for a moment. Falls back silently where the clipboard is denied. */
function CopyPath({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  return (
    <button
      type="button"
      aria-label={copied ? `Copied ${path}` : `Copy path ${path}`}
      onClick={async () => {
        try {
          await navigator.clipboard?.writeText(path);
        } catch {
          // Clipboard refused (permissions, insecure context): the path is still selectable.
        }
        setCopied(true);
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1500);
      }}
      className="relative flex min-h-11 w-full items-center gap-3 overflow-hidden rounded-sm py-2 text-left"
    >
      <span className="min-w-0 flex-1 font-mono text-mono break-all text-on-surface">{path}</span>
      {copied ? (
        <Check className="size-4 shrink-0 text-primary" strokeWidth={1.75} aria-hidden="true" />
      ) : (
        <Copy className="size-4 shrink-0 text-on-surface-muted" strokeWidth={1.75} aria-hidden="true" />
      )}
      <StateLayer />
    </button>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-label text-on-surface-muted">{title}</h3>
      {children}
    </section>
  );
}

function ConnectionsTable({ flows }: { flows: Flow[] }) {
  const sorted = [...flows].sort((a, b) => Number(isActiveFlow(b)) - Number(isActiveFlow(a)));
  const shown = sorted.slice(0, MAX_ROWS);
  if (flows.length === 0) return <p className="text-body text-on-surface-faint">No sockets open right now.</p>;
  return (
    <div>
      <table className="w-full table-fixed text-body" aria-label="Connections">
        <thead>
          <tr className="h-9 text-left text-label text-on-surface-muted">
            <th scope="col" className="pr-3 font-medium">Host</th>
            <th scope="col" className="w-16 px-2 font-medium">Proto</th>
            <th scope="col" className="w-24 px-3 font-medium">State</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((f, i) => (
            <tr key={`${f.proto}-${f.local.port}-${host(f)}-${i}`} data-testid="connection-row" className="h-11">
              <td className="truncate pr-3 font-mono text-mono text-on-surface" data-testid="host">
                {host(f)}
              </td>
              <td className="px-2 text-label text-on-surface-muted uppercase">{f.proto}</td>
              <td className="px-3 text-label text-on-surface-muted">{STATE_LABEL[f.state] ?? f.state}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {sorted.length > MAX_ROWS && (
        <p className="pt-2 text-caption text-on-surface-faint">
          {sorted.length - MAX_ROWS} more not shown
        </p>
      )}
    </div>
  );
}

function RemoteHosts({ flows }: { flows: Flow[] }) {
  const counts = new Map<string, number>();
  for (const f of flows) if (f.remote && isActiveFlow(f)) counts.set(f.remote.addr, (counts.get(f.remote.addr) ?? 0) + 1);
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (rows.length === 0) return <p className="text-body text-on-surface-faint">Not talking to anyone right now.</p>;
  return (
    <ul className="flex flex-col">
      {rows.map(([addr, n]) => (
        <li key={addr} className="flex h-9 items-center gap-3">
          <span className="min-w-0 flex-1 truncate font-mono text-mono text-on-surface">{addr}</span>
          <span className="tabular text-label text-on-surface-muted">{n}</span>
        </li>
      ))}
    </ul>
  );
}

function Detail({ app, actions }: { app: AppEntry; actions: RowActions }) {
  const on = actions.isOn(app.key);
  const pids = app.pids.length;
  const [report, setReport] = useState(false);
  return (
    <div className="flex flex-col gap-6 overflow-y-auto px-5 pb-6">
      <Section title="Sieve">
        {canTurnOff(app.key) ? (
          <>
            <div className="flex items-center gap-3">
              <AppToggle appName={app.name} on={on} onChange={(v) => actions.setOn(app.key, v)} />
              <span className="text-body text-on-surface">{on ? "On" : "Off"}</span>
            </div>
            <p className="text-label text-on-surface-muted" data-testid="app-off-means">
              {APP_OFF_MEANS}
            </p>
            <CardBoundary title="HTTPS">
              <AppExclusionsLine on={on} exes={app.exes} />
            </CardBoundary>
          </>
        ) : (
          <p className="text-body text-on-surface-muted" data-testid="app-no-off">
            Always on. Windows gives this process no name, only a number that another process can have later.
          </p>
        )}
      </Section>

      <CardBoundary title="Problems">
        <AppProblems appKey={app.key} name={app.name} exes={app.exes} canTurnOff={canTurnOff(app.key) && on} turnOff={() => actions.setOn(app.key, false)} />
      </CardBoundary>

      <Section title={app.exes.length === 1 ? "Path" : "Paths"}>
        {app.exes.length === 0 ? (
          <p className="text-body text-on-surface-faint">Windows does not say where this one lives.</p>
        ) : (
          app.exes.map((e) => <CopyPath key={e} path={e} />)
        )}
      </Section>

      <Section title="Executables">
        {pids === 0 ? (
          <p className="text-body text-on-surface-faint">Not running right now.</p>
        ) : (
          <p className="text-body text-on-surface">
            {pids} {pids === 1 ? "process" : "processes"}:{" "}
            <span className="tabular font-mono text-mono text-on-surface-muted">{app.pids.map((p) => `pid ${p}`).join(", ")}</span>
          </p>
        )}
      </Section>

      <Section title={`Connections (${app.activeCount} active)`}>
        <ConnectionsTable flows={app.flows} />
      </Section>

      <Section title="Remote hosts">
        <RemoteHosts flows={app.flows} />
      </Section>

      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" onClick={() => setReport(true)}>
          <Bug strokeWidth={1.75} />
          Report a broken site
        </Button>
        {app.pinnedPaths.length > 0 && (
          <Button variant="destructive" onClick={() => actions.unpin(app.key)}>
            <Trash2 strokeWidth={1.75} />
            Remove from my apps
          </Button>
        )}
      </div>
      <CardBoundary title="Report a broken site">
        <ReportDialog seed={report ? { url: null, exe: iconExe(app) } : null} onClose={() => setReport(false)} />
      </CardBoundary>
    </div>
  );
}

/**
 * An app that is not running: an updater that failed has often exited by the
 * time anyone looks, so its problems and fixes still show, under its key.
 */
function Gone({ appKey, name, actions }: { appKey: string; name: string; actions: RowActions }) {
  const issues = useEngine().issues?.apps.find((a) => a.key === appKey);
  if (!issues) return <EmptyState line="Not here right now" body="This app is not running and is not one of your apps." />;
  return (
    <div className="flex flex-col gap-6 overflow-y-auto px-5 pb-6">
      <CardBoundary title="Problems">
        <AppProblems appKey={appKey} name={name} canTurnOff={canTurnOff(appKey) && actions.isOn(appKey)} turnOff={() => actions.setOn(appKey, false)} />
      </CardBoundary>
    </div>
  );
}

/** Right sheet for one app, opened from a row or straight from `?app=<key>`. */
export function AppDetailSheet({
  appKey,
  app,
  loading,
  known,
  actions,
  onClose,
}: {
  appKey: string | null;
  app: AppEntry | undefined;
  loading: boolean;
  /** Apps and VM rows by key, to name an app that only has problems left. */
  known: readonly { key: string; name: string }[];
  actions: RowActions;
  onClose: () => void;
}) {
  const issue = useEngine().issues?.apps.find((a) => a.key === appKey);
  const title = app?.name ?? (issue ? issueName(issue, known) : (appKey ?? ""));
  return (
    <Sheet open={appKey !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent
        side="right"
        className="gap-0 border-outline bg-surface-1 text-on-surface shadow-l4 data-[side=right]:w-full data-[side=right]:sm:max-w-none data-[side=right]:two:max-w-[480px]"
      >
        <SheetHeader className="flex-row items-center gap-3 p-5 pr-10">
          {app && (
            <AppIcon exe={iconExe(app)} size={40}>
              <Monogram appKey={app.key} name={app.name} size={40} />
            </AppIcon>
          )}
          <div className="min-w-0">
            <SheetTitle className="truncate text-title text-on-surface">{title}</SheetTitle>
            <SheetDescription className="text-label text-on-surface-muted">
              {app
                ? `${CATEGORY_LABEL[app.category]} · ${app.activeCount} active ${app.activeCount === 1 ? "connection" : "connections"}`
                : loading
                  ? "Reading connections"
                  : "Not running"}
            </SheetDescription>
          </div>
        </SheetHeader>
        {app ? (
          <Detail app={app} actions={actions} />
        ) : loading || appKey === null ? null : (
          <Gone appKey={appKey} name={title} actions={actions} />
        )}
      </SheetContent>
    </Sheet>
  );
}
