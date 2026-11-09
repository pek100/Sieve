"use client";

import { useState } from "react";
import { CircleCheck, Info, TriangleAlert } from "lucide-react";
import { FloatingTooltip } from "@/components/sieve/primitives/floating-tooltip";
import { engineStatus } from "@/core/engine";
import type { DnsCapture } from "@/data/protocol";
import { useEngine } from "@/hooks/use-sieve";

/** How the line reads: caught, a fact about this network (nothing is wrong), or a problem. */
export type CaptureTone = "working" | "neutral" | "warning";

/**
 * The Windows DNS errors the DNS Client can return for Sieve's test lookup, in
 * words. Each is about the test lookup, which only Sieve's own server should
 * have answered.
 */
const DNS_CLIENT_ERRORS: Record<number, string> = {
  1460: "Windows gave up on Sieve's test lookup before an answer came",
  9001: "a DNS server could not read Sieve's test lookup",
  9002: "a DNS server failed on Sieve's test lookup",
  9003: "another DNS server answered Sieve's test lookup before Sieve did",
  9004: "a DNS server does not take lookups like Sieve's test",
  9005: "a DNS server refused Sieve's test lookup",
  9502: "the answer to Sieve's test lookup came back damaged",
};

/** The DNS Client's error in words, or null for a code with none. */
export function dnsClientError(code: number | undefined): string | null {
  return code === undefined ? null : (DNS_CLIENT_ERRORS[code] ?? null);
}

/** What the row says of the capture the engine reports, or null when there is nothing to say. */
export function captureStateLine(c: DnsCapture | undefined): { tone: CaptureTone; text: string; code?: number } | null {
  if (c === undefined || c.state === "off") return null;
  if (c.state === "working") return { tone: "working", text: "Working: Windows' own lookups go through Sieve now." };
  const still = "Until then they go to your network's DNS server, as without Sieve.";
  switch (c.reason) {
    case "tie":
      return { tone: "warning", text: `Not working: the network adapter "${c.adapter ?? "another adapter"}" has priority 1, so Windows asks it first. Give it a priority above 1 to fix this. ${still}` };
    case "ipv6_off":
      return { tone: "warning", text: `Not working: IPv6 is off on Sieve's network adapter, and Sieve takes Windows' lookups over IPv6. ${still}` };
    case "no_answer":
      return { tone: "warning", text: `Not working: Sieve's test lookup never reached it. A firewall rule or another program is in the way. ${still}` };
    case "no_ipv4":
      return { tone: "neutral", text: "Not on this network: it has no IPv4 route to the internet, so Windows keeps asking the network's own DNS server." };
    case "nothing_to_catch":
      return { tone: "neutral", text: "Nothing to do on this network: none of Windows' lookups would leave outside Sieve." };
    case "failed": {
      // A code the DNS Client returned is said in words, the raw number kept for the tooltip.
      const words = dnsClientError(c.code);
      if (words !== null) return { tone: "warning", text: `Not working: ${words}. ${still}`, code: c.code };
      return { tone: "warning", text: `Not working: ${c.detail}. ${still}`, ...(c.code === undefined ? {} : { code: c.code }) };
    }
  }
}

const ICONS = { working: CircleCheck, neutral: Info, warning: TriangleAlert } as const;
const ICON_COLOR = { working: "text-primary", neutral: "text-on-surface-muted", warning: "text-warning" } as const;

/**
 * The capture's live state under "Also encrypt Windows' own lookups", from the
 * engine's status (`dns_capture`). Nothing while the switch is off, while routes
 * are down, or from an engine that does not report it. A Windows error code is
 * in words; the number itself is in the tooltip, for a support question.
 */
export function DnsCaptureState() {
  const line = captureStateLine(engineStatus(useEngine())?.dns_capture);
  const [at, setAt] = useState<{ x: number; y: number } | null>(null);
  if (line === null) return null;
  const Icon = ICONS[line.tone];
  const code = line.code;
  return (
    <p
      data-capture-state={line.tone === "working" ? "working" : "not_caught"}
      data-capture-tone={line.tone}
      className="flex items-start gap-2 pt-1 text-label text-on-surface-muted"
      onPointerMove={code === undefined ? undefined : (e) => setAt({ x: e.clientX, y: e.clientY })}
      onPointerLeave={code === undefined ? undefined : () => setAt(null)}
    >
      <Icon aria-hidden="true" className={`size-4 shrink-0 ${ICON_COLOR[line.tone]}`} strokeWidth={1.75} />
      <span className="min-w-0">{line.text}</span>
      {code !== undefined && at !== null && (
        <FloatingTooltip x={at.x} y={at.y} data-capture-code={String(code)}>
          Windows DNS error {code}
        </FloatingTooltip>
      )}
    </p>
  );
}
