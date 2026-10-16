"use client";

import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { useRuntime } from "@/hooks/sieve-provider";
import { useNotices } from "@/hooks/use-sieve";

/**
 * Renders toast notices from the notice bus (B7) through sonner. Code never
 * calls sonner directly: it pushes to runtime.notices, so banners and
 * desktop notifications can read the same queue later.
 */
export function NoticeToaster() {
  const { notices } = useRuntime();
  const list = useNotices();
  const shown = useRef(new Set<number>());

  useEffect(() => {
    for (const n of list) {
      if (n.surface !== "toast" || shown.current.has(n.id)) continue;
      shown.current.add(n.id);
      const show = n.kind === "error" ? toast.error : n.kind === "success" ? toast.success : toast.info;
      show(n.text, {
        id: n.id,
        duration: 4000,
        action: n.action ? { label: n.action.label, onClick: () => n.action?.run() } : undefined,
        onDismiss: () => notices.dismiss(n.id),
        onAutoClose: () => notices.dismiss(n.id),
      });
    }
  }, [list, notices]);

  return <Toaster position="bottom-right" />;
}
