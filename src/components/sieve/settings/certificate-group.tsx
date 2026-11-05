"use client";

import { KeyRound } from "lucide-react";
import { useState, type ReactNode } from "react";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  CERT_STATE_TEXT,
  CERT_STATE_UNKNOWN,
  FIREFOX_TEXT,
  HTTPS_SWITCH,
  certInstalled,
  engineLockReason,
  httpsInForce,
} from "@/core/engine";
import { useEngine, useEngineActions, useSetting } from "@/hooks/use-sieve";
import { useRuntime } from "@/hooks/sieve-provider";

/** The day of a fact the engine gave, or null when it is not one. */
function day(ms: number | null | undefined): string | null {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-h-11 flex-wrap items-center justify-between gap-x-4">
      <dt className="text-label text-on-surface-muted">{label}</dt>
      <dd className="min-w-0 text-body text-on-surface">{children}</dd>
    </div>
  );
}

function RemoveDialog({ onCancel, onRemove }: { onCancel: () => void; onRemove: () => void }) {
  return (
    <DialogContent className="bg-surface-3 text-on-surface sm:max-w-lg">
      <DialogHeader>
        <DialogTitle className="text-title">Remove certificate</DialogTitle>
        <DialogDescription className="text-body text-on-surface-muted">
          This turns HTTPS filtering off and removes Sieve&apos;s certificate from Windows and Firefox.
        </DialogDescription>
      </DialogHeader>
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="destructive" onClick={onRemove}>
          Remove certificate
        </Button>
      </div>
    </DialogContent>
  );
}

/**
 * Settings > Filtering, the root certificate (plan 8.1), from the engine's
 * facts only (owner: the engine controller). Flat like every block. A row
 * with no fact is left out, never a dash; with no root only the state line
 * shows; with no answer from the engine the state is unknown and one line
 * says why. Reinstall makes a new root while the engine holds HTTPS on;
 * Remove turns the switch off, which is what removes the root.
 */
export function CertificateGroup() {
  const e = useEngine();
  const { installRoot } = useEngineActions();
  const { notices } = useRuntime();
  const [, setHttps] = useSetting(HTTPS_SWITCH);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const lock = engineLockReason(e);
  const cert = lock === null ? (e.cert ?? null) : null;
  const unanswered = lock !== null || Boolean(e.certError);
  const installed = certInstalled(cert);
  const state = unanswered ? CERT_STATE_UNKNOWN : cert ? (CERT_STATE_TEXT[cert.state] ?? CERT_STATE_UNKNOWN) : "Checking";
  const problem = lock === null && e.certError ? `Sieve could not read the certificate: ${e.certError}` : (cert?.last_error ?? null);
  const validUntil = installed ? day(cert?.valid_until_ms) : null;
  const rotated = installed ? day(cert?.last_rotation_ms) : null;
  const thumbprint = installed ? (cert?.thumbprint ?? null) : null;
  const firefox = installed && cert ? (FIREFOX_TEXT[cert.firefox] ?? null) : null;

  const copy = () => {
    const done = navigator.clipboard?.writeText(thumbprint ?? "") ?? Promise.reject(new Error("no clipboard"));
    done.then(
      () => notices.push({ kind: "success", text: "Thumbprint copied" }),
      () => notices.push({ kind: "error", text: "Could not copy. Select the thumbprint and copy it by hand." }),
    );
  };

  const reinstall = async () => {
    setBusy(true);
    try {
      await installRoot();
    } finally {
      setBusy(false);
    }
  };

  const remove = () => {
    setConfirming(false);
    setHttps(false).catch(() => notices.push({ kind: "error", text: "Could not save the change, so the certificate was not removed." }));
  };

  return (
    <Card title="Certificate" icon={<KeyRound strokeWidth={1.75} />}>
      <div className="flex flex-col gap-4" data-certificate-group="">
        <div className="flex flex-col gap-1">
          <p role="status" className="text-body text-on-surface" data-certificate-state="">
            {state}
          </p>
          {lock !== null && <p className="text-label text-on-surface-muted break-words">{lock}</p>}
          {problem && (
            <p role="alert" className="text-label text-blocked break-words" data-certificate-error="">
              {problem}
            </p>
          )}
        </div>
        {installed && (validUntil || thumbprint || firefox || rotated) && (
          <dl className="flex flex-col">
            {validUntil && <Row label="Valid until">{validUntil}</Row>}
            {thumbprint && (
              <Row label="Thumbprint">
                <button
                  type="button"
                  onClick={copy}
                  aria-label={`Copy thumbprint ${thumbprint}`}
                  className="relative overflow-hidden rounded-sm text-left font-mono text-mono break-all"
                  data-certificate-thumbprint=""
                >
                  {thumbprint}
                  <StateLayer />
                </button>
              </Row>
            )}
            {firefox && <Row label="Firefox">{firefox}</Row>}
            {rotated && <Row label="Last rotation">{rotated}</Row>}
          </dl>
        )}
        {(httpsInForce(e) || installed) && (
          <div className="flex flex-wrap gap-2">
            {httpsInForce(e) && (
              <Button variant="secondary" disabled={busy} onClick={() => void reinstall()}>
                {busy ? "Reinstalling certificate" : "Reinstall certificate"}
              </Button>
            )}
            {installed && (
              <Button variant="secondary" onClick={() => setConfirming(true)}>
                Remove certificate
              </Button>
            )}
          </div>
        )}
        {e.certActionError && (
          <p role="alert" className="text-label text-blocked break-words" data-certificate-action-error="">
            {e.certActionError}
          </p>
        )}
      </div>
      <Dialog open={confirming} onOpenChange={setConfirming}>
        {confirming && <RemoveDialog onCancel={() => setConfirming(false)} onRemove={remove} />}
      </Dialog>
    </Card>
  );
}
