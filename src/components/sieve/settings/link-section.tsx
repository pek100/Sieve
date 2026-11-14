"use client";

import { CircleCheck, Info, Route as RouteIcon, TriangleAlert } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { LockedNote } from "@/components/sieve/lock/locked-note";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { Segmented } from "@/components/sieve/primitives/segmented";
import { StateLayer } from "@/components/sieve/primitives/state-layer";
import { Card } from "@/components/sieve/shell/card";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { engineRoutes, engineStatus } from "@/core/engine";
import {
  DEFAULT_LISTEN_PORT,
  DIAL_FROM_CODE_TEXT,
  DIAL_HINT_TEXT,
  HUB_DOWN_TEXT,
  LINK_NORMAL_TEXT,
  LINK_NOT_THROUGH_TEXT,
  LINK_TITLE,
  UDP_TEXT,
  codeProblem,
  dialAddressProblem,
  hubName,
  isPaired,
  linkDnsText,
  linkPrivacyText,
  linkStateLine,
  linkThroughText,
  linkUdpText,
  listenText,
  parsePort,
  shortFingerprint,
  withSetting,
  type LinkTone,
} from "@/core/link";
import { isShut } from "@/core/lock";
import type { LinkRoute, LinkSettings, LinkStatus } from "@/data/protocol";
import { useRuntime } from "@/hooks/sieve-provider";
import { useLock } from "@/hooks/use-lock";
import { useEngine, useLinkActions } from "@/hooks/use-sieve";

const ICONS = { working: CircleCheck, neutral: Info, warning: TriangleAlert } as const;
const ICON_COLOR = { working: "text-primary", neutral: "text-on-surface-muted", warning: "text-warning" } as const;
const inputClass = "h-9 rounded-sm bg-inset px-3 text-body shadow-inset";

function StateLine({ tone, text }: { tone: LinkTone; text: string }) {
  const Icon = ICONS[tone];
  return (
    <p role="status" data-link-state-line={tone} className="flex items-start gap-2 text-body text-on-surface">
      <Icon aria-hidden="true" className={`mt-0.5 size-4 shrink-0 ${ICON_COLOR[tone]}`} strokeWidth={1.75} />
      <span className="min-w-0 break-words">{text}</span>
    </p>
  );
}

/** One row on the settings grid: the words on the left, the control on the right. */
function Row({ id, label, help, children }: { id: string; label: string; help?: ReactNode; children?: ReactNode }) {
  return (
    <div role="group" aria-labelledby={`${id}-label`} data-link-row={id} className="flex min-h-11 flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <div className="min-w-0 flex-1 basis-60">
        <p id={`${id}-label`} className="text-body-strong text-on-surface">
          {label}
        </p>
        {help && <div className="text-label text-on-surface-muted">{help}</div>}
      </div>
      {children && <div className="flex max-w-full min-w-0 items-center">{children}</div>}
    </div>
  );
}

/** A fingerprint, shortened, with the whole of it on hover and on copy. */
function Fingerprint({ label, value }: { label: string; value: string }) {
  const { notices } = useRuntime();
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  const copy = () => {
    const done = navigator.clipboard?.writeText(value) ?? Promise.reject(new Error("no clipboard"));
    done.then(
      () => notices.push({ kind: "success", text: `${label} copied` }),
      () => notices.push({ kind: "error", text: "Could not copy. Hover the fingerprint and copy it by hand." }),
    );
  };
  return (
    <div className="flex min-h-11 flex-wrap items-center justify-between gap-x-4">
      <dt className="text-label text-on-surface-muted">{label}</dt>
      <dd className="min-w-0 text-body text-on-surface">
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label.toLowerCase()} ${value}`}
          onPointerMove={(e) => setAt({ x: e.clientX, y: e.clientY })}
          onPointerLeave={() => setAt(null)}
          className="relative overflow-hidden rounded-sm text-left font-mono text-mono"
          data-link-fingerprint={value}
        >
          {shortFingerprint(value)}
          <StateLayer />
        </button>
        {at !== null && (
          <FloatingTooltip x={at.x} y={at.y} className="max-w-96 font-mono break-all" data-link-fingerprint-full="">
            {value}
          </FloatingTooltip>
        )}
      </dd>
    </div>
  );
}

type How = LinkRoute["how"];
const HOW_ITEMS = (disabled: boolean) => [
  { value: "dial" as const, label: "This computer dials", disabled },
  { value: "listen" as const, label: "The other device dials", disabled },
];

/** How the two meet: dial an address, or listen on a port. `optionalAddress`: the code carries one. */
function RouteFields({
  how,
  address,
  port,
  disabled,
  optionalAddress,
  onHow,
  onAddress,
  onPort,
}: {
  how: How;
  address: string;
  port: string;
  disabled: boolean;
  optionalAddress: boolean;
  onHow: (h: How) => void;
  onAddress: (v: string) => void;
  onPort: (v: string) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      <Segmented label="How the two devices meet" size="touch" items={HOW_ITEMS(disabled)} value={how} onChange={onHow} className="self-start" />
      {how === "dial" ? (
        <label className="flex flex-col gap-1 text-label text-on-surface-muted">
          The other device&apos;s address
          <Input value={address} onChange={(e) => onAddress(e.target.value)} disabled={disabled} placeholder="203.0.113.20:7443" spellCheck={false} autoComplete="off" className={inputClass} data-link-address="" />
          <span>
            {DIAL_HINT_TEXT}
            {optionalAddress && ` ${DIAL_FROM_CODE_TEXT}`}
          </span>
        </label>
      ) : (
        <label className="flex flex-col gap-1 text-label text-on-surface-muted">
          The TCP port this computer opens
          <Input value={port} onChange={(e) => onPort(e.target.value)} disabled={disabled} inputMode="numeric" spellCheck={false} autoComplete="off" className={`${inputClass} w-32`} data-link-port="" />
          <span>{listenText(parsePort(port) ?? port)}</span>
        </label>
      )}
    </div>
  );
}

/** The route the fields say, or why they cannot. A dial with no address is None: the code's own. */
function routeOf(how: How, address: string, port: string, optionalAddress: boolean): { route: LinkRoute | undefined } | { problem: string } {
  if (how === "listen") {
    const p = parsePort(port);
    return p === null ? { problem: "Choose a port from 1 to 65535." } : { route: { how: "listen", port: p } };
  }
  const problem = dialAddressProblem(address, optionalAddress);
  if (problem !== null) return { problem };
  return { route: address.trim() === "" ? undefined : { how: "dial", address: address.trim() } };
}

/**
 * Unpaired: paste the code (masked, as a password is, and gone from the field
 * the moment it is sent), choose how the two meet, Pair. The code lives in this
 * field's state only: never in settings, storage, a log or an error.
 */
function PairForm({ disabled }: { disabled: boolean }) {
  const { linkPair } = useLinkActions();
  const [code, setCode] = useState("");
  const [how, setHow] = useState<How>("dial");
  const [address, setAddress] = useState("");
  const [port, setPort] = useState(String(DEFAULT_LISTEN_PORT));
  const [problem, setProblem] = useState<string | null>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const bad = codeProblem(code);
    if (bad !== null) return setProblem(bad);
    const r = routeOf(how, address, port, true);
    if ("problem" in r) return setProblem(r.problem);
    setProblem(null);
    const sent = code;
    // Gone from the field before it leaves: never shown again, whatever the answer.
    setCode("");
    void linkPair(sent, r.route);
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-4" data-link-pair-form="">
      <label className="flex flex-col gap-1 text-label text-on-surface-muted">
        Pairing code from the other device
        <Input
          type="password"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          placeholder="SL1-..."
          className={inputClass}
          data-link-code=""
        />
        <span>Run the hub on the other device to get one. Sieve sends it to its engine once and keeps no copy.</span>
      </label>
      <RouteFields how={how} address={address} port={port} disabled={disabled} optionalAddress onHow={setHow} onAddress={setAddress} onPort={setPort} />
      {problem && (
        <p role="alert" className="text-label text-blocked">
          {problem}
        </p>
      )}
      <div>
        <Button type="submit" disabled={disabled}>
          Pair
        </Button>
      </div>
    </form>
  );
}

/** The route of a paired device, editable; saved whole with the rest of the choices. */
function RouteEditor({ settings, disabled, onSave }: { settings: LinkSettings; disabled: boolean; onSave: (s: LinkSettings) => void }) {
  const held = settings.route;
  const [how, setHow] = useState<How>(held.how);
  const [address, setAddress] = useState(held.how === "dial" ? held.address : "");
  const [port, setPort] = useState(String(held.how === "listen" ? held.port : DEFAULT_LISTEN_PORT));
  const [problem, setProblem] = useState<string | null>(null);
  const r = routeOf(how, address, port, false);
  const changed = "route" in r ? JSON.stringify(r.route) !== JSON.stringify(held) : true;
  const save = () => {
    if ("problem" in r) return setProblem(r.problem);
    setProblem(null);
    if (r.route) onSave(withSetting(settings, "route", r.route));
  };
  return (
    <div className="flex flex-col gap-3" data-link-route-editor="">
      <RouteFields how={how} address={address} port={port} disabled={disabled} optionalAddress={false} onHow={setHow} onAddress={setAddress} onPort={setPort} />
      {problem && (
        <p role="alert" className="text-label text-blocked">
          {problem}
        </p>
      )}
      {changed && (
        <div>
          <Button variant="secondary" disabled={disabled} onClick={save}>
            Save how they meet
          </Button>
        </div>
      )}
    </div>
  );
}

function UnpairDialog({ name, onCancel, onUnpair }: { name: string; onCancel: () => void; onUnpair: () => void }) {
  return (
    <DialogContent className="bg-surface-3 text-on-surface sm:max-w-lg">
      <DialogHeader>
        <DialogTitle className="text-title">Unpair {name}</DialogTitle>
        <DialogDescription className="text-body text-on-surface-muted">
          This removes {name} and this computer&apos;s key for it. Nothing leaves through it any more, and pairing again needs a new code from the other device.
        </DialogDescription>
      </DialogHeader>
      <div className="flex flex-wrap justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="destructive" onClick={onUnpair}>
          Unpair
        </Button>
      </div>
    </DialogContent>
  );
}

/** What it does, what it does not, what breaks, who sees what: plainly. */
function About({ name, settings }: { name: string; settings: LinkSettings | undefined }) {
  return (
    <div className="flex flex-col gap-2 text-label text-on-surface-muted" data-link-about="">
      <p>{linkThroughText(name)}</p>
      <p>{LINK_NOT_THROUGH_TEXT}</p>
      <p>{linkUdpText(name)}</p>
      {/* Paired, the UDP row says what its choice breaks; before pairing it is said here, for the default. */}
      {settings === undefined && <p>{`By default, UDP is ${UDP_TEXT.drop.charAt(0).toLowerCase()}${UDP_TEXT.drop.slice(1)}`}</p>}
      <p>{linkDnsText(name)}</p>
      <p>{linkPrivacyText(name)}</p>
      <p>{LINK_NORMAL_TEXT}</p>
    </div>
  );
}

function Paired({ link, disabled, routes }: { link: LinkStatus & { settings: LinkSettings }; disabled: boolean; routes: boolean }) {
  const { setLink, linkUnpair } = useLinkActions();
  const [confirming, setConfirming] = useState(false);
  const s = link.settings;
  const name = hubName(link);
  return (
    <div className="flex flex-col gap-4">
      {(link.hub_name || link.hub_fingerprint || link.device_fingerprint) && (
        <dl className="flex flex-col">
          {link.hub_name && (
            <div className="flex min-h-11 flex-wrap items-center justify-between gap-x-4">
              <dt className="text-label text-on-surface-muted">Other device</dt>
              <dd className="min-w-0 text-body text-on-surface break-words">{link.hub_name}</dd>
            </div>
          )}
          {link.hub_fingerprint && <Fingerprint label="Its fingerprint" value={link.hub_fingerprint} />}
          {link.device_fingerprint && <Fingerprint label="This computer's fingerprint" value={link.device_fingerprint} />}
        </dl>
      )}
      <Row id="link-exit" label={`Exit through ${name}`} help={routes ? "Sieved apps' connections leave through it while this is on." : "Sieve routes nothing now, so nothing leaves through it until it does."}>
        <Switch checked={s.exit} disabled={disabled} onCheckedChange={(v) => void setLink(withSetting(s, "exit", v))} aria-labelledby="link-exit-label" />
      </Row>
      <Row id="link-hub-down" label={`When ${name} cannot be reached`} help={HUB_DOWN_TEXT[s.on_hub_down]}>
        <Segmented
          label={`When ${name} cannot be reached`}
          items={[
            { value: "stop" as const, label: "Stop", disabled },
            { value: "direct" as const, label: "Go direct", disabled },
          ]}
          value={s.on_hub_down}
          onChange={(v) => void setLink(withSetting(s, "on_hub_down", v))}
        />
      </Row>
      <Row id="link-udp" label="Other UDP" help={UDP_TEXT[s.udp]}>
        <Segmented
          label="Other UDP"
          items={[
            { value: "drop" as const, label: "Drop", disabled },
            { value: "direct" as const, label: "Send directly", disabled },
          ]}
          value={s.udp}
          onChange={(v) => void setLink(withSetting(s, "udp", v))}
        />
      </Row>
      <Row id="link-route" label="How the two devices meet" />
      {/* Remounted when the engine's route changes, so the fields start from what it holds. */}
      <RouteEditor key={JSON.stringify(s.route)} settings={s} disabled={disabled} onSave={(next) => void setLink(next)} />
      <About name={name} settings={s} />
      <div>
        <Button variant="secondary" disabled={disabled} onClick={() => setConfirming(true)}>
          Unpair
        </Button>
      </div>
      <Dialog open={confirming} onOpenChange={setConfirming}>
        {confirming && (
          <UnpairDialog
            name={name}
            onCancel={() => setConfirming(false)}
            onUnpair={() => {
              setConfirming(false);
              void linkUnpair();
            }}
          />
        )}
      </Dialog>
    </div>
  );
}

/**
 * Settings, exiting through another device: shown only when the engine's
 * status carries `link` (an older engine: nothing at all). Reading is open;
 * pairing, unpairing and every change pass the settings password. Flat like
 * every block.
 */
export function LinkSection({ now = Date.now }: { now?: () => number }) {
  const e = useEngine();
  const { state } = useLock();
  const link = engineStatus(e)?.link;
  if (!link) return null;
  const shut = isShut(state.phase);
  const busy = e.linkBusy === true;
  const routes = engineRoutes(e);
  const line = linkStateLine(link, routes, now());
  return (
    <Card title={LINK_TITLE} icon={<RouteIcon strokeWidth={1.75} />}>
      <div className="flex flex-col gap-4" data-link-section={link.state}>
        <StateLine tone={line.tone} text={line.text} />
        {shut && <LockedNote phase={state.phase} />}
        {e.linkActionError && (
          <p role="alert" className="text-label text-blocked break-words" data-link-error="">
            {e.linkActionError}
          </p>
        )}
        {isPaired(link) ? (
          <Paired link={link} disabled={shut || busy} routes={routes} />
        ) : link.state === "unpaired" ? (
          <>
            <PairForm disabled={shut || busy} />
            <About name="the other device" settings={undefined} />
          </>
        ) : null}
      </div>
    </Card>
  );
}
