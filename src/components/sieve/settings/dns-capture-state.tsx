"use client";

import { CircleCheck, TriangleAlert } from "lucide-react";
import { engineStatus } from "@/core/engine";
import type { DnsCapture } from "@/data/protocol";
import { useEngine } from "@/hooks/use-sieve";

/** What the row says of the capture the engine reports, or null when there is nothing to say. */
export function captureStateLine(c: DnsCapture | undefined): { working: boolean; text: string } | null {
  if (c === undefined || c.state === "off") return null;
  if (c.state === "working") return { working: true, text: "Working: Windows' own lookups go through Sieve now." };
  const still = "Until then they go to your network's DNS server, as without Sieve.";
  switch (c.reason) {
    case "tie":
      return { working: false, text: `Not working: the network adapter "${c.adapter ?? "another adapter"}" has priority 1, so Windows asks it first. Give it a priority above 1 to fix this. ${still}` };
    case "ipv6_off":
      return { working: false, text: `Not working: IPv6 is off on Sieve's network adapter, and Sieve takes Windows' lookups over IPv6. ${still}` };
    case "no_answer":
      return { working: false, text: `Not working: Sieve's test lookup never reached it. A firewall rule or another program is in the way. ${still}` };
    case "no_ipv4":
      return { working: false, text: "Not on this network: it has no IPv4 route to the internet, so Windows keeps asking the network's own DNS server." };
    case "failed":
      return { working: false, text: `Not working: ${c.detail}. ${still}` };
  }
}

/**
 * The capture's live state under "Also encrypt Windows' own lookups", from the
 * engine's status (`dns_capture`). Nothing while the switch is off, while routes
 * are down, or from an engine that does not report it.
 */
export function DnsCaptureState() {
  const line = captureStateLine(engineStatus(useEngine())?.dns_capture);
  if (line === null) return null;
  const Icon = line.working ? CircleCheck : TriangleAlert;
  return (
    <p data-capture-state={line.working ? "working" : "not_caught"} className="flex items-start gap-2 pt-1 text-label text-on-surface-muted">
      <Icon aria-hidden="true" className={line.working ? "size-4 shrink-0 text-primary" : "size-4 shrink-0 text-warning"} strokeWidth={1.75} />
      <span className="min-w-0">{line.text}</span>
    </p>
  );
}
