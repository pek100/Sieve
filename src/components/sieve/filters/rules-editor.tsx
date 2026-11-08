"use client";

import { ScrollText } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { checkRuleText, friendlyRuleReason, normalizeDomain, withFormRules, type RuleForm } from "@/core/rules";
import type { RuleProblem } from "@/data/protocol";
import type { RuleSave } from "@/hooks/use-filters";

const ACTIONS = [
  { value: "block", label: "Block" },
  { value: "allow", label: "Allow" },
] as const;

/** What the form's rule does, said before it is added. */
export function formMeaning(form: Pick<RuleForm, "action" | "subdomains">, host: string): string {
  if (form.action === "block") return form.subdomains ? `Blocks ${host} and every address under it, such as www.${host}.` : `Blocks ${host} only, not its subdomains.`;
  return form.subdomains ? `Lets ${host} and every address under it through, even when a list blocks them.` : `Lets ${host} through, but not its subdomains, even when a list blocks it.`;
}

/**
 * The one rule editor: the rule form (a site, block or allow, its subdomains, a
 * note), which writes the lines for you, then the raw text, with friendly
 * per-line words under it. A rule the form adds is saved at once when nothing
 * is being edited; otherwise it joins the unsaved text, which the person saves.
 */
export function RulesEditor({ saved, onSave, disabled }: { saved: readonly string[]; onSave: (lines: string[]) => Promise<RuleSave>; disabled: boolean }) {
  const savedText = saved.join("\n");
  // Null while nothing was typed: the editor then follows what is stored (an import, an undo).
  const [draft, setDraft] = useState<string | null>(null);
  const [refused, setRefused] = useState<RuleProblem[]>([]);
  // Why the last save failed: the parser could not be asked, or the write did not land.
  const [saveFailed, setSaveFailed] = useState<string | null>(null);
  // Checks run in parallel and finish in any order, so one save at a time keeps the last click the last write.
  const [saving, setSaving] = useState(false);
  const [site, setSite] = useState("");
  const [siteError, setSiteError] = useState<string | null>(null);
  const [action, setAction] = useState<RuleForm["action"]>("block");
  const [subdomains, setSubdomains] = useState(true);
  const [comment, setComment] = useState("");
  const [added, setAdded] = useState<string | null>(null);
  const text = draft ?? savedText;
  const check = useMemo(() => checkRuleText(text), [text]);
  const notes = check.notes.flatMap((l) => (l.check.kind === "error" || l.check.kind === "hint" ? [{ n: l.n, kind: l.check.kind, message: l.check.message }] : []));
  const dirty = draft !== null && draft !== savedText;

  const edit = (next: string) => {
    setDraft(next);
    setRefused([]);
    setSaveFailed(null);
  };

  const addRule = (e: FormEvent) => {
    e.preventDefault();
    const host = normalizeDomain(site);
    if (!host.ok) return setSiteError(host.error);
    setSiteError(null);
    const next = withFormRules(text, { host: host.host, action, subdomains, comment });
    setSite("");
    setComment("");
    if (next === text) return setAdded("That rule is already there.");
    if (dirty) {
      edit(next);
      setAdded("Added to your unsaved rules below. Save them to apply it.");
      return;
    }
    setAdded(null);
    void save(next);
  };

  const save = async (from: string = text) => {
    const lines = checkRuleText(from);
    setSaveFailed(null);
    setSaving(true);
    let result: RuleSave;
    try {
      result = await onSave(lines.stored);
    } catch (e) {
      setSaveFailed(e instanceof Error ? e.message : String(e));
      return;
    } finally {
      setSaving(false);
    }
    // The parser counts stored lines; the person reads the editor's, blanks included.
    const editorLines = lines.lines.filter((l) => l.check.kind !== "blank");
    setRefused(result.refused.map((p) => ({ line: editorLines[p.line - 1]?.n ?? p.line, reason: p.reason })));
    // Only what was stored leaves the editor: not a write the lock dropped, nor what was typed since.
    if (result.saved) {
      setDraft((d) => (d === null || d === from ? null : d));
      if (from !== text) setAdded("Rule added.");
    } else if (from !== text) {
      // Not stored: the form's lines stay in the editor, so nothing typed is lost.
      setDraft(from);
    }
  };

  return (
    <Card title="User rules" icon={<ScrollText strokeWidth={1.75} />}>
      <div className="flex flex-col gap-3" data-rules-editor="">
        <form onSubmit={addRule} className="flex flex-col gap-2" data-rule-form="">
          <div className="flex flex-wrap items-center gap-2">
            <Segmented label="What the rule does" items={ACTIONS.map((a) => ({ ...a, disabled }))} value={action} onChange={setAction} size="touch" />
            <Input
              value={site}
              onChange={(e) => {
                setSite(e.target.value);
                setAdded(null);
              }}
              disabled={disabled}
              aria-label="Site"
              placeholder="example.com"
              spellCheck={false}
              className="h-9 min-w-0 flex-1 basis-48 rounded-sm bg-inset px-3 font-mono text-mono shadow-inset"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex min-h-11 items-center gap-2 text-label text-on-surface">
              <Switch checked={subdomains} onCheckedChange={setSubdomains} disabled={disabled} aria-label="Include subdomains" />
              Include subdomains
            </label>
            <Input
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              disabled={disabled}
              aria-label="Note (optional)"
              placeholder="Note (optional)"
              className="h-9 min-w-0 flex-1 basis-40 rounded-sm bg-inset px-3 text-body shadow-inset"
            />
            <Button type="submit" variant="secondary" disabled={disabled || saving || site.trim() === ""}>
              Add rule
            </Button>
          </div>
          {(() => {
            const host = normalizeDomain(site);
            return site.trim() !== "" && host.ok ? (
              <p className="text-label text-on-surface-muted" data-rule-meaning="">
                {formMeaning({ action, subdomains }, host.host)}
              </p>
            ) : null;
          })()}
          {siteError && (
            <p role="alert" className="text-label text-blocked">
              {siteError}
            </p>
          )}
          {added && (
            <p role="status" className="text-label text-on-surface-muted" data-rule-added="">
              {added}
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
        {(notes.length > 0 || refused.length > 0 || check.tooLong || saveFailed !== null) && (
          <ul aria-label="Rule problems" className="flex flex-col gap-1 text-label">
            {check.tooLong && (
              <li role="alert" className="text-blocked">
                {check.tooLong}
              </li>
            )}
            {saveFailed !== null && (
              <li role="alert" className="text-blocked" data-rule-note="save">
                These rules were not saved: Sieve could not check or store them. <span className="font-mono text-mono text-on-surface-muted">{saveFailed}</span>
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
          <Button disabled={disabled || saving || !dirty || !check.canSave} onClick={() => void save(text)}>
            Save rules
          </Button>
        </div>
      </div>
    </Card>
  );
}
