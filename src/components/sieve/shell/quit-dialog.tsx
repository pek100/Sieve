"use client";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useDns, useDnsActions } from "@/hooks/use-sieve";

/**
 * Asked when the app is about to end (tray Quit, the close button) while
 * Windows uses Sieve for DNS: ending Sieve ends the filter, and Windows
 * would keep asking a server that is gone. Three answers, the safe one first.
 */
export function QuitDialog() {
  const { quitAsked, busy } = useDns();
  const actions = useDnsActions();
  return (
    <Dialog open={quitAsked} onOpenChange={(o) => !o && actions.cancelQuit()}>
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto bg-surface-3 text-on-surface sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-title">Windows uses Sieve for DNS</DialogTitle>
          <DialogDescription className="text-body text-on-surface-muted">
            Quitting stops Sieve&apos;s DNS filter. Restore your DNS first, or names on this computer stop resolving until Sieve runs
            again.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex flex-col gap-2 sm:flex-col">
          <Button disabled={busy !== null} onClick={() => void actions.quit("restore")}>
            Restore DNS and quit
          </Button>
          <Button
            variant="destructive"
            className="h-auto min-h-9 py-2 whitespace-normal"
            disabled={busy !== null}
            onClick={() => void actions.quit("keep")}
          >
            Keep filtering, internet stops resolving until Sieve runs again
          </Button>
          <Button variant="ghost" onClick={() => actions.cancelQuit()}>
            Cancel
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
