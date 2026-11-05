"use client";

import { Cpu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/sieve/shell/card";
import {
  ADGUARD_PAUSE_TEXT,
  ADGUARD_START_TEXT,
  ENGINE_PROBLEMS,
  ENGINE_STATE_TEXT,
  adguardOffer,
  attribution,
  engineDetail,
  enginePhase,
  engineStatus,
  engineVersion,
  hostAttribution,
  splitTunnelText,
} from "@/core/engine";
import { useEngine, useEngineActions } from "@/hooks/use-sieve";
import { cn } from "@/lib/utils";

const percent = (share: number) => `${Math.floor(share * 1000) / 10}%`;

/**
 * Settings > Filtering, the engine: what Sieve's filtering engine is, from
 * facts only (the Windows service's state and the engine's own answer on its
 * pipe; owner: the engine controller). The installer installs it; the
 * "Route traffic through the engine" switch above turns its routing on.
 * Flat like every block: a title, a status line, one sentence on what it
 * means, then what the engine itself reported: split tunnels, its flow
 * counters, its version. While AdGuard's service blocks it, the pause offer
 * says exactly what it does (it stops that service; Windows asks first) and
 * "Start AdGuard again" undoes it.
 */
export function EngineCard() {
  const e = useEngine();
  const { stopAdguard, startAdguard } = useEngineActions();
  const phase = enginePhase(e);
  const version = engineVersion(e);
  const offer = adguardOffer(e);
  const split = splitTunnelText(e);
  const share = attribution(e);
  const hostShare = hostAttribution(e);
  const flows = engineStatus(e)?.counters.flows ?? 0;
  const forwarded = engineStatus(e)?.counters.forwarded ?? 0;
  const busy = e.adguard ?? null;

  return (
    <Card title="Engine" icon={<Cpu strokeWidth={1.75} />} tone={phase === "routing" ? "mint" : "neutral"}>
      <div className="flex flex-col gap-4" data-engine-card="" data-engine-phase={phase}>
        <div className="flex flex-col gap-1">
          <p role="status" className="text-body text-on-surface" data-engine-state="">
            {ENGINE_STATE_TEXT[phase]}
          </p>
          <p
            role={ENGINE_PROBLEMS.has(phase) ? "alert" : undefined}
            className={cn("text-label break-words", ENGINE_PROBLEMS.has(phase) ? "text-blocked" : "text-on-surface-muted")}
            data-engine-detail=""
          >
            {engineDetail(e)}
          </p>
          {split && (
            <p className="text-label text-on-surface-muted break-words" data-engine-split="">
              {split}
            </p>
          )}
          {share !== null && (
            <p className="text-label text-on-surface-muted" data-engine-attribution="">
              <span className="tabular">{flows.toLocaleString("en-US")}</span> flows relayed since the engine started,{" "}
              <span className="tabular">{percent(share)}</span> tied to an app.
              {forwarded > 0 && hostShare !== null && (
                <>
                  {" "}
                  <span className="tabular">{forwarded.toLocaleString("en-US")}</span> came from virtual machines;{" "}
                  <span className="tabular">{percent(hostShare)}</span> of this computer&apos;s own flows are tied to an app.
                </>
              )}
            </p>
          )}
          {version && (
            <p className="text-label text-on-surface-muted">
              Engine version <span className="font-mono text-mono">{version}</span>
            </p>
          )}
        </div>
        {offer && (
          <div className="flex flex-col items-start gap-2" data-adguard-offer={offer}>
            <p className="text-label text-on-surface-muted break-words">{offer === "pause" ? ADGUARD_PAUSE_TEXT : ADGUARD_START_TEXT}</p>
            {offer === "pause" ? (
              <Button variant="secondary" disabled={busy !== null} onClick={() => void stopAdguard()}>
                {busy === "stopping" ? "Pausing AdGuard" : "Pause AdGuard"}
              </Button>
            ) : (
              <Button variant="secondary" disabled={busy !== null} onClick={() => void startAdguard()}>
                {busy === "starting" ? "Starting AdGuard" : "Start AdGuard again"}
              </Button>
            )}
          </div>
        )}
        {e.actionError && (
          <p role="alert" className="text-label text-blocked break-words" data-engine-action-error="">
            {e.actionError}
          </p>
        )}
      </div>
    </Card>
  );
}
