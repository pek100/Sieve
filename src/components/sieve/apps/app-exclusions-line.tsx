"use client";

import Link from "next/link";
import { useExclusionRows } from "@/components/sieve/settings/use-exclusions";
import { appDecryption, exclusionsHref } from "@/core/exclusions";
import { useEngine } from "@/hooks/use-sieve";

/**
 * One line under an app's switch: what Sieve does with this app's HTTPS, true for
 * what the engine does (plan 8.2, task D8). Nothing while it is not known, and
 * nothing for an Off app: the switch's own line says that.
 */
export function AppExclusionsLine({ on, exes }: { on: boolean; exes: readonly string[] }) {
  const e = useEngine();
  const rows = useExclusionRows();
  const said = appDecryption(e, { on, exes }, rows);
  if (said.line === null) return null;
  return (
    <p className="text-label text-on-surface-muted" data-testid="app-https">
      {said.apps.length === 0 ? (
        said.line
      ) : (
        <Link href={exclusionsHref(said.apps)} className="underline underline-offset-2 hover:text-on-surface">
          {said.line}
        </Link>
      )}
    </p>
  );
}
