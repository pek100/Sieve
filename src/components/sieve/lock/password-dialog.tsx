"use client";

import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { MIN_PASSWORD_CHARS, passwordProblem } from "@/core/lock";
import { useLock } from "@/hooks/use-lock";

export type PasswordAction = "set" | "change" | "remove";

const WORDS: Record<PasswordAction, { title: string; body: string; button: string }> = {
  set: { title: "Set a password", body: `Use at least ${MIN_PASSWORD_CHARS} characters. Sieve keeps only a hash of it, never the password.`, button: "Set password" },
  change: { title: "Change the password", body: `Use at least ${MIN_PASSWORD_CHARS} characters. Sieve keeps only a hash of it, never the password.`, button: "Change password" },
  remove: { title: "Remove the password", body: "Anyone at this computer can then change settings and read the log.", button: "Remove password" },
};

const inputClass = "h-9 rounded-sm bg-inset px-3 text-body shadow-inset";
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

function Field({ label, value, onChange, autoFocus, autoComplete }: { label: string; value: string; onChange: (v: string) => void; autoFocus?: boolean; autoComplete: string }) {
  return (
    <label className="flex flex-col gap-1 text-label text-on-surface-muted">
      {label}
      <Input type="password" autoFocus={autoFocus} autoComplete={autoComplete} value={value} onChange={(e) => onChange(e.target.value)} className={inputClass} />
    </label>
  );
}

/** Set, change or remove the settings password. Rust checks it again and holds the hash. */
export function PasswordDialog({ action, onClose }: { action: PasswordAction; onClose: () => void }) {
  const { lock } = useLock();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const words = WORDS[action];
  const needsCurrent = action !== "set";
  const needsNext = action !== "remove";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const problem = needsNext ? passwordProblem(next, repeat) : null;
    if (problem) return setError(problem);
    setBusy(true);
    setError(null);
    try {
      if (action === "remove") await lock.clearPassword(current);
      else await lock.setPassword(needsCurrent ? current : null, next);
      onClose();
    } catch (err) {
      setError(message(err));
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="bg-surface-3 text-on-surface sm:max-w-sm" data-password-dialog={action}>
        <DialogHeader>
          <DialogTitle className="text-title">{words.title}</DialogTitle>
          <DialogDescription className="text-body text-on-surface-muted">{words.body}</DialogDescription>
        </DialogHeader>
        <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3">
          {needsCurrent && <Field label="Current password" value={current} onChange={setCurrent} autoFocus autoComplete="current-password" />}
          {needsNext && (
            <>
              <Field label="New password" value={next} onChange={setNext} autoFocus={!needsCurrent} autoComplete="new-password" />
              <Field label="New password again" value={repeat} onChange={setRepeat} autoComplete="new-password" />
            </>
          )}
          {error && (
            <p role="alert" className="text-label text-blocked">
              {error}
            </p>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" variant={action === "remove" ? "destructive" : "default"} disabled={busy}>
              {words.button}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
