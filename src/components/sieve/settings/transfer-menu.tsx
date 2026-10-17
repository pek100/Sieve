"use client";

import { Download, FileUp, MoreVertical, RotateCcw } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";
import { IconButton } from "@/components/sieve/primitives/icon-button";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import type { SettingsDoc } from "@/core/settings/document";
import { settingDef } from "@/core/settings/registry";
import { exportText, formatValue, type Change, type ImportPlan, type Refused } from "@/core/settings/transfer";
import { useRuntime } from "@/hooks/sieve-provider";
import type { SettingsView } from "./use-settings-view";

const itemClass = "h-9 gap-3 rounded-sm px-3 text-body";
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

function Sheet({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto bg-surface-3 text-on-surface sm:max-w-lg">
      <DialogHeader>
        <DialogTitle className="text-title">{title}</DialogTitle>
        <DialogDescription className="text-body text-on-surface-muted">{description}</DialogDescription>
      </DialogHeader>
      {children}
    </DialogContent>
  );
}

/** The change preview: one line per key, before and after, then what was refused and why. */
export function ChangeList({ changes, refused = [] }: { changes: readonly Change[]; refused?: readonly Refused[] }) {
  return (
    <div className="flex flex-col gap-3">
      {changes.length === 0 ? (
        <p className="text-body text-on-surface-muted">Nothing would change.</p>
      ) : (
        <ul aria-label="Changes" className="flex flex-col gap-1 rounded-md bg-inset p-3 shadow-inset">
          {changes.map((c) => (
            <li key={c.key} className="flex flex-wrap items-baseline justify-between gap-x-3 text-body">
              <span className="text-on-surface">{settingDef(c.key).label}</span>
              <span className="text-label text-on-surface-muted tabular">
                {formatValue(c.key, c.from)} <span aria-hidden="true">to</span>
                <span className="sr-only">changes to</span> <span className="text-on-surface">{formatValue(c.key, c.to)}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
      {refused.length > 0 && (
        <ul aria-label="Not imported" className="flex flex-col gap-1">
          {refused.map((r) => (
            <li key={r.key} className="text-label text-on-surface-muted">
              <code className="font-mono text-mono text-on-surface">{r.key}</code>: {r.reason}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ExportDialog({ doc, onClose }: { doc: SettingsDoc; onClose: () => void }) {
  const { notices } = useRuntime();
  const text = exportText(doc);
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "sieve-settings.json";
    a.click();
    URL.revokeObjectURL(url);
  };
  const copy = () =>
    navigator.clipboard?.writeText(text).then(
      () => notices.push({ kind: "success", text: "Settings copied" }),
      () => notices.push({ kind: "error", text: "Could not copy. Select the text and copy it by hand." }),
    );
  return (
    <Sheet title="Export settings" description="Only the settings you changed are in the file. Import it on any Sieve.">
      <textarea
        readOnly
        value={text}
        aria-label="Exported settings"
        className="h-48 w-full resize-none rounded-md bg-inset p-3 font-mono text-mono text-on-surface shadow-inset outline-none"
      />
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Done
        </Button>
        <Button variant="secondary" onClick={() => void copy()}>
          Copy
        </Button>
        <Button onClick={download}>
          <Download strokeWidth={1.75} />
          Download
        </Button>
      </div>
    </Sheet>
  );
}

function ImportDialog({ view, onClose }: { view: SettingsView; onClose: () => void }) {
  const [text, setText] = useState("");
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const file = useRef<HTMLInputElement>(null);

  if (plan?.ok) {
    return (
      <Sheet title="Import settings" description="Check what changes before anything is applied. Settings not in the file go back to their defaults.">
        <ChangeList changes={plan.changes} refused={plan.refused} />
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" onClick={() => setPlan(null)}>
            Back
          </Button>
          <Button
            disabled={plan.changes.length === 0}
            onClick={() => {
              view.apply(plan.next, `Imported ${plural(plan.changes.length, "change", "changes")}`);
              onClose();
            }}
          >
            {plan.changes.length === 0 ? "Nothing to apply" : `Apply ${plural(plan.changes.length, "change", "changes")}`}
          </Button>
        </div>
      </Sheet>
    );
  }

  return (
    <Sheet title="Import settings" description="Paste an exported settings file or choose one. You see the changes before they apply.">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        aria-label="Settings file to import"
        placeholder="Paste exported settings here"
        spellCheck={false}
        className="h-40 w-full resize-none rounded-md bg-inset p-3 font-mono text-mono text-on-surface shadow-inset outline-none placeholder:text-on-surface-faint"
      />
      {plan && !plan.ok && (
        <p role="alert" className="text-body text-blocked">
          {plan.error}
        </p>
      )}
      <input
        ref={file}
        type="file"
        accept="application/json,.json"
        className="sr-only"
        tabIndex={-1}
        aria-label="Settings file"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) void f.text().then((t) => setText(t));
        }}
      />
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="secondary" onClick={() => file.current?.click()}>
          <FileUp strokeWidth={1.75} />
          Choose file
        </Button>
        <Button disabled={text.trim() === ""} onClick={() => setPlan(view.planImport(text))}>
          Preview changes
        </Button>
      </div>
    </Sheet>
  );
}

function ResetDialog({ view, onClose }: { view: SettingsView; onClose: () => void }) {
  const [plan] = useState(() => view.resetAll());
  return (
    <Sheet title="Reset every setting?" description="Every setting goes back to its default. You can undo it right after.">
      <ChangeList changes={plan.changes} />
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          variant="destructive"
          disabled={plan.changes.length === 0}
          onClick={() => {
            view.apply(plan.next, "Settings reset to defaults");
            onClose();
          }}
        >
          Reset to defaults
        </Button>
      </div>
    </Sheet>
  );
}

type Open = "export" | "import" | "reset" | null;

/** The settings overflow menu: export, import (with a preview), reset to defaults (with a confirm). */
export function TransferMenu({ view }: { view: SettingsView }) {
  const [open, setOpen] = useState<Open>(null);
  const close = () => setOpen(null);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <IconButton label="Settings actions">
            <MoreVertical strokeWidth={1.75} />
          </IconButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-auto min-w-52 rounded-md bg-surface-3 p-1 shadow-l3">
          <DropdownMenuItem className={itemClass} onSelect={() => setOpen("export")}>
            <Download strokeWidth={1.75} />
            Export settings
          </DropdownMenuItem>
          <DropdownMenuItem className={itemClass} onSelect={() => setOpen("import")}>
            <FileUp strokeWidth={1.75} />
            Import settings
          </DropdownMenuItem>
          <DropdownMenuItem className={itemClass} onSelect={() => setOpen("reset")}>
            <RotateCcw strokeWidth={1.75} />
            Reset to defaults
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog open={open !== null} onOpenChange={(o) => !o && close()}>
        {open === "export" && <ExportDialog doc={view.doc} onClose={close} />}
        {open === "import" && <ImportDialog view={view} onClose={close} />}
        {open === "reset" && <ResetDialog view={view} onClose={close} />}
      </Dialog>
    </>
  );
}
