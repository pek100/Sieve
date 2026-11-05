"use client";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { LinePreview } from "@/core/log-actions";

/** Shows the exact line before anything is written (plan 8.3: "after preview"). */
export function RulePreview({ preview, onConfirm, onCancel }: { preview: LinePreview | null; onConfirm: () => void; onCancel: () => void }) {
  return (
    <Dialog open={preview !== null} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="bg-surface-3 text-on-surface sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-title break-all">{preview?.title}</DialogTitle>
          <DialogDescription className="text-body text-on-surface-muted">{preview?.body}</DialogDescription>
        </DialogHeader>
        <code data-rule-preview="" className="block rounded-md bg-inset p-3 font-mono text-mono break-all text-on-surface shadow-inset">
          {preview?.line}
        </code>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button onClick={onConfirm}>Add it</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
