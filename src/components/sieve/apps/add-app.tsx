"use client";

import { Plus } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { isPinnablePath } from "@/core/apps-actions";
import { useRuntime } from "@/hooks/sieve-provider";
import { useHydrated } from "@/hooks/use-hydrated";

/** Tauri: the native file dialog, filtered to programs. Returns the chosen path or null. */
async function pickExe(): Promise<string | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const picked = await open({
    title: "Add an app",
    multiple: false,
    directory: false,
    filters: [{ name: "Programs", extensions: ["exe"] }],
  });
  return typeof picked === "string" ? picked : null;
}

/**
 * "Add app" pill CTA. In Tauri it opens the system file dialog for an .exe;
 * in a plain browser (no file paths there) it asks for the path as text.
 */
export function AddApp({ onAdd }: { onAdd: (path: string) => void }) {
  const { isTauri, notices } = useRuntime();
  const hydrated = useHydrated();
  const [open, setOpen] = useState(false);
  const [path, setPath] = useState("");
  const [touched, setTouched] = useState(false);
  const inputId = useId();
  const errorId = useId();
  const valid = isPinnablePath(path);

  const start = async () => {
    if (!(hydrated && isTauri)) {
      setPath("");
      setTouched(false);
      setOpen(true);
      return;
    }
    try {
      const picked = await pickExe();
      if (picked) onAdd(picked);
    } catch (e) {
      notices.push({ kind: "error", text: `Could not open the file picker: ${e instanceof Error ? e.message : String(e)}` });
    }
  };

  return (
    <>
      <Button onClick={() => void start()}>
        <span data-icon="inline-start" className="inline-flex size-6 items-center justify-center rounded-full bg-on-primary/12">
          <Plus strokeWidth={1.75} />
        </span>
        Add app
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="bg-surface-3 text-on-surface">
          <DialogHeader>
            <DialogTitle className="text-title">Add an app</DialogTitle>
            <DialogDescription className="text-body text-on-surface-muted">
              Paste the full path of a program. It stays under Mine, even when it is not running.
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              setTouched(true);
              if (!valid) return;
              onAdd(path);
              setOpen(false);
            }}
          >
            <div className="flex flex-col gap-2">
              <label htmlFor={inputId} className="text-label text-on-surface-muted">
                Program path
              </label>
              <input
                id={inputId}
                value={path}
                onChange={(e) => setPath(e.target.value)}
                onBlur={() => setTouched(true)}
                placeholder="C:\Program Files\App\app.exe"
                spellCheck={false}
                autoComplete="off"
                aria-invalid={touched && !valid}
                aria-describedby={touched && !valid ? errorId : undefined}
                className="h-10 w-full rounded-full bg-inset px-4 font-mono text-mono text-on-surface shadow-inset outline-none placeholder:text-on-surface-faint focus-visible:outline-2 focus-visible:outline-primary aria-invalid:outline-[1.5px] aria-invalid:outline-blocked"
              />
              {touched && !valid && (
                <p id={errorId} className="text-label text-blocked">
                  Enter a path that ends in .exe
                </p>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit">Add</Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
