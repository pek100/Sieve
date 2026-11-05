"use client";

import { ScrollText } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { blockRule, checkRuleText, friendlyRuleReason, normalizeDomain } from "@/core/rules";
import type { RuleProblem } from "@/data/protocol";

/** The one rule editor: a text area, friendly per-line words under it, and "Block a site", which writes the rule for you. */
export function RulesEditor({ saved, onSave, disabled }: { saved: readonly string[]; onSave: (lines: string[]) => Promise<RuleProblem[]>; disabled: boolean }) {
  const savedText = saved.join("\n");
  // Null while nothing was typed: the editor then follows what is stored (an import, an undo).
  const [draft, setDraft] = useState<string | null>(null);
  const [refused, setRefused] = useState<RuleProblem[]>([]);
  const [site, setSite] = useState("");
  const [siteError, setSiteError] = useState<string | null>(null);
  const text = draft ?? savedText;
  const check = useMemo(() => checkRuleText(text), [text]);
  const notes = check.notes.flatMap((l) => (l.check.kind === "error" || l.check.kind === "hint" ? [{ n: l.n, kind: l.check.kind, message: l.check.message }] : []));
  const dirty = draft !== null && draft !== savedText;

  const edit = (next: string) => {
    setDraft(next);
    setRefused([]);
  };

  const blockSite = (e: FormEvent) => {
    e.preventDefault();
    const host = normalizeDomain(site);
    if (!host.ok) return setSiteError(host.error);
    setSiteError(null);
    setSite("");
    const rule = blockRule(host.host);
    if (text.split(/\r?\n/).some((l) => l.trim() === rule)) return;
    edit(text.trim() === "" ? rule : `${text.replace(/\s+$/, "")}\n${rule}`);
  };

  const save = async () => {
    const problems = await onSave(check.stored);
    // The parser counts stored lines; the person reads the editor's, blanks included.
    const editorLines = check.lines.filter((l) => l.check.kind !== "blank");
    setRefused(problems.map((p) => ({ line: editorLines[p.line - 1]?.n ?? p.line, reason: p.reason })));
    if (problems.length === 0) setDraft(null);
  };

  return (
    <Card title="User rules" icon={<ScrollText strokeWidth={1.75} />}>
      <div className="flex flex-col gap-3" data-rules-editor="">
        <form onSubmit={blockSite} className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Input
              value={site}
              onChange={(e) => setSite(e.target.value)}
              disabled={disabled}
              aria-label="Block a site"
              placeholder="Block a site, such as example.com"
              spellCheck={false}
              className="h-9 flex-1 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset"
            />
            <Button type="submit" variant="secondary" disabled={disabled || site.trim() === ""}>
              Add rule
            </Button>
          </div>
          {siteError && (
            <p role="alert" className="text-label text-blocked">
              {siteError}
            </p>
          )}
        </form>
        <textarea
          value={text}
          onChange={(e) => edit(e.target.value)}
          readOnly={disabled}
          aria-label="User rules"
          placeholder={"||example.com^\n! Lines starting with ! are notes"}
          spellCheck={false}
          className="h-44 w-full resize-y rounded-md bg-inset p-3 font-mono text-mono text-on-surface shadow-inset outline-none placeholder:text-on-surface-faint"
        />
        {(notes.length > 0 || refused.length > 0 || check.tooLong) && (
          <ul aria-label="Rule problems" className="flex flex-col gap-1 text-label">
            {check.tooLong && (
              <li role="alert" className="text-blocked">
                {check.tooLong}
              </li>
            )}
            {notes.map((n) => (
              <li key={n.n} role={n.kind === "error" ? "alert" : undefined} className={n.kind === "error" ? "text-blocked" : "text-on-surface-muted"} data-rule-note={n.kind}>
                Line <span className="tabular">{n.n}</span>: {n.message}
              </li>
            ))}
            {refused.map((p) => (
              <li key={`parser-${p.line}`} role="alert" className="text-blocked" data-rule-note="parser">
                Line <span className="tabular">{p.line}</span>: {friendlyRuleReason(p.reason)} <span className="font-mono text-mono text-on-surface-muted">{p.reason}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="flex justify-end">
          <Button disabled={disabled || !dirty || !check.canSave} onClick={() => void save()}>
            Save rules
          </Button>
        </div>
      </div>
    </Card>
  );
}
