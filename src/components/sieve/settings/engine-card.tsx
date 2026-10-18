"use client";

import { Cpu } from "lucide-react";
import { Card } from "@/components/sieve/shell/card";
import { ENGINE_STATE_TEXT, engineDetail, enginePhase, engineVersion, type EnginePhase } from "@/core/engine";
import { useEngine } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";

/** Phases whose detail is a problem the user should read. */
const PROBLEMS: ReadonlySet<EnginePhase> = new Set<EnginePhase>(["unreadable", "refused", "incompatible"]);

/**
 * Settings > Filtering, the engine: what Sieve's filtering engine is, from
 * facts only (the Windows service's state and the engine's own answer on its
 * pipe; owner: the engine controller). Read only: the installer installs it,
 * nothing here starts or stops it. Flat like every block: a title, a status
 * line, one sentence on what it means, the engine's version when it said it.
 */
export function EngineCard() {
  const e = useEngine();
  const phase = enginePhase(e);
  const version = engineVersion(e);

  return (
    <Card title="Engine" icon={<Cpu strokeWidth={1.75} />} tone={phase === "filtering" ? "mint" : "neutral"}>
      <div className="flex flex-col gap-1" data-engine-card="" data-engine-phase={phase}>
        <p role="status" className="text-body text-on-surface" data-engine-state="">
          {ENGINE_STATE_TEXT[phase]}
        </p>
        <p
          role={PROBLEMS.has(phase) ? "alert" : undefined}
          className={cn("text-label break-words", PROBLEMS.has(phase) ? "text-blocked" : "text-on-surface-muted")}
          data-engine-detail=""
        >
          {engineDetail(e)}
        </p>
        {version && (
          <p className="text-label text-on-surface-muted">
            Engine version <span className="font-mono text-mono">{version}</span>
          </p>
        )}
      </div>
    </Card>
  );
}
