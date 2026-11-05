"use client";

import { Check, Copy, ExternalLink } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { engineLists, engineStatus } from "@/core/engine";
import { buildReport, hasQuery, issuePage, reportList, rulesForPage, stripQuery } from "@/core/report";
import { BROWSER_VERSION } from "@/data/desktop";
import { useRuntime } from "@/hooks/sieve-provider";
import { useEngine, useLog } from "@/hooks/use-sieve";
import type { ReportSeed } from "./use-log";

const NO_FACTS = "The engine has not reported its filter lists, so there is no issue page to open.";
const NO_PAGE = "This list has no public issue page.";

/**
 * The form, mounted only while the dialog is open, so it starts from the seed
 * each time. Nothing here sends anything: "Copy report" writes the clipboard,
 * and "Open issue page" writes it and opens the list's public page, with
 * nothing of the report in the URL.
 */
function ReportForm({ seed, onClose }: { seed: ReportSeed; onClose: () => void }) {
  const { notices, pages } = useRuntime();
  const e = useEngine();
  const { rows } = useLog();
  const lists = engineLists(e);
  const resourcePin = engineStatus(e)?.filter?.resource_pin ?? null;

  // Query strings carry tokens: out by default, and back only by the user's hand.
  const full = seed.url ?? "";
  const stripped = stripQuery(full);
  const [url, setUrl] = useState(stripped);
  const [version, setVersion] = useState(BROWSER_VERSION);
  const [copied, setCopied] = useState(false);
  const [picked, setPicked] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void pages.appVersion().then(
      (v) => live && setVersion(v),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, [pages]);

  const rules = useMemo(() => rulesForPage(rows, url, seed.exe), [rows, url, seed.exe]);
  const list = lists.find((l) => l.id === picked) ?? reportList(rules, lists);
  const page = list ? issuePage(list.homepage) : null;
  const reason = list === null ? NO_FACTS : page === null ? NO_PAGE : null;
  const text = buildReport({ url, browser: seed.exe, lists, rules, resourcePin, sieveVersion: version });

  /** Writes the report to the clipboard; a refusal is said, and the text stays selectable. */
  const copy = async (): Promise<boolean> => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      notices.push({ kind: "error", text: "Could not copy. Select the report's text and copy it by hand." });
      return false;
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <label htmlFor="report-url" className="text-label text-on-surface-muted">
          Page URL
        </label>
        <Input id="report-url" value={url} spellCheck={false} placeholder="The page that broke" onChange={(ev) => setUrl(ev.target.value)} className="font-mono text-mono" />
        {hasQuery(full) && url === stripped && (
          <div>
            <Button variant="ghost" size="sm" onClick={() => setUrl(full)}>
              Add the query string back
            </Button>
          </div>
        )}
      </div>

      {lists.length > 0 && list && (
        <div className="flex flex-col gap-2">
          <p id="report-list" className="text-label text-on-surface-muted">
            Goes to the issue page of
          </p>
          <Select value={list.id} onValueChange={setPicked}>
            <SelectTrigger aria-labelledby="report-list" className="h-9 w-full rounded-full bg-inset px-3 text-label">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {lists.map((l) => (
                <SelectItem key={l.id} value={l.id}>
                  {l.title}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      <div className="flex flex-col gap-2">
        <label htmlFor="report-text" className="text-label text-on-surface-muted">
          The report
        </label>
        <textarea
          id="report-text"
          readOnly
          value={text}
          className="h-44 w-full resize-none rounded-md bg-inset p-3 font-mono text-mono text-on-surface shadow-inset outline-none"
        />
        <p className="text-label text-on-surface-muted">Sieve sends nothing. You choose where this goes.</p>
      </div>

      {reason && (
        <p className="text-label text-on-surface-muted" data-report-no-page="">
          {reason}
        </p>
      )}

      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Done
        </Button>
        <Button
          variant="secondary"
          onClick={() =>
            void copy().then((ok) => {
              setCopied(ok);
              if (ok) notices.push({ kind: "success", text: "Report copied" });
            })
          }
        >
          {copied ? <Check strokeWidth={1.75} /> : <Copy strokeWidth={1.75} />}
          Copy report
        </Button>
        <Button
          disabled={page === null}
          onClick={() => {
            if (page === null) return;
            // The page opens whether or not the clipboard took it.
            void copy()
              .then((ok) => {
                setCopied(ok);
                return pages.openExternal(page);
              })
              .catch((err: unknown) => notices.push({ kind: "error", text: `Could not open the page: ${err instanceof Error ? err.message : String(err)}` }));
          }}
        >
          <ExternalLink strokeWidth={1.75} />
          Open issue page
        </Button>
      </div>
    </div>
  );
}

/** Report a broken site (plan 8.4), from a log row or the app sheet. Assembled here; nothing is sent. */
export function ReportDialog({ seed, onClose }: { seed: ReportSeed | null; onClose: () => void }) {
  return (
    <Dialog open={seed !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto bg-surface-3 text-on-surface sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-title">Report a broken site</DialogTitle>
          <DialogDescription className="text-body text-on-surface-muted">Check the URL first: it goes into a public issue if you post it.</DialogDescription>
        </DialogHeader>
        {seed && <ReportForm seed={seed} onClose={onClose} />}
      </DialogContent>
    </Dialog>
  );
}
