"use client";

import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useLock } from "@/hooks/use-lock";

function UnlockForm() {
  const { state, lock } = useLock();
  const [password, setPassword] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void lock.unlock(password);
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <Input
        type="password"
        autoFocus
        autoComplete="current-password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        aria-label="Password"
        aria-invalid={state.error !== null || undefined}
        className="h-9 rounded-sm bg-inset px-3 text-body shadow-inset"
      />
      {state.error && (
        <p role="alert" className="text-label text-blocked">
          {state.error}
        </p>
      )}
      <div className="flex flex-wrap justify-end gap-2">
        <Button type="button" variant="ghost" onClick={() => lock.cancel()}>
          Cancel
        </Button>
        <Button type="submit" disabled={state.busy || password === ""}>
          Unlock
        </Button>
      </div>
    </form>
  );
}

/** The one unlock prompt, mounted once in the shell. It opens whenever the write gate asks; closing it drops what was waiting. */
export function UnlockDialog() {
  const { state, lock } = useLock();
  return (
    <Dialog open={state.asking} onOpenChange={(open) => !open && lock.cancel()}>
      {state.asking && (
        <DialogContent className="bg-surface-3 text-on-surface sm:max-w-sm" data-unlock-dialog="">
          <DialogHeader>
            <DialogTitle className="text-title">Unlock settings</DialogTitle>
            <DialogDescription className="text-body text-on-surface-muted">Type your Sieve password to change settings.</DialogDescription>
          </DialogHeader>
          <UnlockForm />
        </DialogContent>
      )}
    </Dialog>
  );
}
