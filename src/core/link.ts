/**
 * Exiting through another device (a Sieve link hub), the pure part: what the
 * app says about it, from the engine's `link` fact only. Nothing here keeps or
 * repeats a pairing code: the code goes from the field to the engine once and
 * nowhere else. An engine that sends no `link` fact cannot do this, and the app
 * then says nothing of it at all.
 */
import type { ExitVia, LinkHubDown, LinkRoute, LinkSettings, LinkStatus, LinkUdp } from "@/data/protocol";

/** The Settings section's title and anchor. */
export const LINK_TITLE = "Exit through another device";
export const LINK_ANCHOR = "exit-device";
/** The port the listen choice starts with. */
export const DEFAULT_LISTEN_PORT = 7443;
/** sieve-ipc `LINK_CODE_MAX`: a longer paste is not a code. */
export const CODE_MAX = 512;

/** The other device's own name, or plain words when it gave none. */
export const hubName = (l: Pick<LinkStatus, "hub_name"> | null | undefined): string => l?.hub_name ?? "the other device";

const capital = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** A paired state: the hub's record exists. */
export const isPaired = (l: LinkStatus | null | undefined): l is LinkStatus & { settings: LinkSettings } =>
  l !== null && l !== undefined && l.settings !== undefined && l.state !== "unpaired" && l.state !== "pairing";

/** A fingerprint shortened for a line: its first and last eight characters. The full one is on hover and copy. */
export function shortFingerprint(fp: string): string {
  return fp.length > 20 ? `${fp.slice(0, 8)}...${fp.slice(-8)}` : fp;
}

/** A clock time for `since_ms`, with the day when it is not today's (both passed in: core reads no clock). */
export function sinceWords(ms: number | undefined, now: number): string | null {
  if (typeof ms !== "number" || !Number.isFinite(ms) || ms <= 0) return null;
  const at = new Date(ms);
  if (Number.isNaN(at.getTime())) return null;
  const time = at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return new Date(now).toDateString() === at.toDateString() ? `since ${time}` : `since ${at.toLocaleDateString([], { month: "short", day: "numeric" })}, ${time}`;
}

/** What a sieved app's new connection meets while the other device cannot be reached, in the setting's words. */
export function hubDownConsequence(onHubDown: LinkHubDown): string {
  return onHubDown === "direct"
    ? "sieved apps leave directly from this computer, from its own address"
    : "sieved apps' new connections are stopped rather than leaving from this computer's own address";
}

export type LinkTone = "working" | "neutral" | "warning";

/**
 * The live line under the section's title: the state, since when, the last
 * error and the open port, in words. `routes`: Sieve routes traffic now (exit
 * needs it). `now` is the caller's clock, for "since".
 */
export function linkStateLine(l: LinkStatus, routes: boolean, now: number): { tone: LinkTone; text: string } {
  const name = hubName(l);
  const since = sinceWords(l.since_ms, now);
  const at = since ? ` ${since}` : "";
  const why = l.last_error ? ` The last error: ${l.last_error}.` : "";
  const listen = l.listening ? ` Listening for ${name} on ${l.listening}.` : "";
  const onDown = l.settings?.on_hub_down ?? "stop";
  switch (l.state) {
    case "unpaired":
      return l.last_error ? { tone: "warning", text: `Not paired. The last pairing did not work: ${l.last_error}.` } : { tone: "neutral", text: "Not paired with another device." };
    case "pairing":
      return {
        tone: "neutral",
        text: l.listening
          ? `Pairing: waiting for the other device to connect to ${l.listening}, for as long as the code is valid (about 10 minutes).`
          : "Pairing with the other device. When the other device dials this computer, Sieve waits for it as long as the code is valid (about 10 minutes).",
      };
    case "off":
      // The engine says off while Sieve is paused too: exiting stops with it.
      if (l.settings?.exit === true)
        return { tone: "neutral", text: `Paired with ${name}. Exiting through it is on, and waits while Sieve is paused: until Sieve is on again, apps leave from this computer's own address.${why}` };
      return { tone: "neutral", text: `Paired with ${name}${at}. Exiting through it is off: apps leave from this computer's own address.${why}` };
    case "connecting":
      if (!routes) return { tone: "neutral", text: `Exiting through ${name} is on. It starts when Sieve routes traffic; until then this computer's network works as usual.` };
      return { tone: "warning", text: `Connecting to ${name}${at}. Until it answers, ${hubDownConsequence(onDown)}.${listen}${why}` };
    case "up":
      return { tone: "working", text: `Exiting through ${name}${at}. Sites see its address, not this computer's.${listen}` };
    case "down":
      return { tone: "warning", text: `${capital(name)} cannot be reached${at}, so ${hubDownConsequence(onDown)}.${listen}${why}` };
    case "unknown":
      return { tone: "neutral", text: `This version of Sieve cannot name the state of the link to ${name}.${why}` };
  }
}

/** Home's line about exiting. `offerOff`: the line comes with one button that turns exiting off. */
export type LinkHomeLine = { tone: "neutral" | "warning"; text: string; offerOff?: true };

/** The button that ends a stop Sieve never ends by itself. */
export const LINK_OFF_LABEL = "Turn off exiting";

/**
 * Home's line while exiting through the other device is on and Sieve routes:
 * a short line while it is up, a notice while it cannot be reached (what the
 * hub-down setting does to sieved apps). Null otherwise: nothing to say.
 *
 * Stopped is the one state Sieve never leaves by itself (it never goes direct
 * on its own): when the other device cannot be reached (the engine says down
 * once the link was up and went, and also once it has tried for about 20
 * seconds without ever reaching it, as after a move to another network or a
 * restart), or the network wants a sign-in (`signIn`: the status's
 * `wifi_sign_in`) while the connections are stopped, the line says why plainly
 * and offers to turn exiting off. It sits beside the sign-in notice, which is
 * about DNS: both may be needed.
 */
export function linkHomeLine(l: LinkStatus | null | undefined, routes: boolean, signIn = false): LinkHomeLine | null {
  if (!l || l.settings?.exit !== true || !routes) return null;
  const name = hubName(l);
  const onDown = l.settings.on_hub_down;
  const stuck = onDown === "stop" && (l.state === "down" || (l.state === "connecting" && signIn));
  if (stuck) {
    const why = signIn ? `This network wants a sign-in, and ${name} cannot be reached from it until you sign in` : `${capital(name)} cannot be reached from this network`;
    // The sign-in notice's button is about lookups; this one is about connections. Signing in can need both.
    const how = signIn ? "To sign in, turn exiting off, and use the sign-in button too if its page still does not open" : "To get online, turn exiting off";
    return {
      tone: "warning",
      text: `${why}. Sieved apps' connections are stopped, as set: Sieve never sends them from this computer's own address by itself. ${how}; turn it on again in Settings when ${name} can be reached.`,
      offerOff: true,
    };
  }
  switch (l.state) {
    case "up":
      return { tone: "neutral", text: `Exiting through ${name}: sites see its address, not this computer's.` };
    case "connecting":
      return { tone: "warning", text: `Connecting to ${name}. Until it answers, ${hubDownConsequence(onDown)}.` };
    case "down":
      return { tone: "warning", text: `${capital(name)} cannot be reached, so ${hubDownConsequence(onDown)}.` };
    default:
      return null;
  }
}

/** The hub-down choice in words. */
export const HUB_DOWN_TEXT: Readonly<Record<LinkHubDown, string>> = {
  stop: "Stop sieved apps' new connections, and DNS lookups through it, rather than letting them leave from this computer's own address.",
  direct: "Go direct: sieved apps leave from this computer's own address until the other device is back.",
};

/** The UDP choice in words, with what each breaks or gives away. */
export const UDP_TEXT: Readonly<Record<LinkUdp, string>> = {
  drop: "Dropped. These stop working while exiting is on: online games, voice and video calls, WebRTC in browsers (video meetings), torrents' uTP and DHT, some VPNs, and anything else built on UDP.",
  direct: "Sent directly from this computer. Those apps work, but they leave from this computer's own address.",
};

/** What goes through the other device and what Sieve still does first. */
export const linkThroughText = (name: string) =>
  `While this is on and Sieve routes traffic, every TCP connection a sieved app makes to the internet leaves through ${name}, and sites see its address, not this computer's. Sieve asks ${name} to connect by the name the connection itself carries (the site's name in HTTPS and web requests), else by the address the app chose. Turning this on or off, or a change of network, ends sieved apps' open connections to the internet, so they reconnect the new way. Sieve still filters first: blocking, apps you turned off, HTTPS filtering (the real site's certificate is still checked end to end), tracking protection and the log work as before.`;

/** What never goes through it. */
export const LINK_NOT_THROUGH_TEXT =
  "Not through it: connections of apps you turned off in Sieve, and everything while Sieve is paused (they go out directly, as without it); this computer's own local network; Sieve's own filter list and update downloads and its Wi-Fi sign-in checks. Sieve's encrypted DNS lookups are the exception for apps you turned off: Sieve cannot tell which app asked for a name, so their lookups go through the other device too.";

/** UDP and QUIC. */
export const linkUdpText = (name: string) =>
  `The link carries TCP only. Browsers are asked not to use QUIC, so web pages fall back to TCP and go through ${name}. Other UDP to the internet is dropped, or sent directly from this computer if you choose.`;

/** DNS: encryption stays the owner's choice, never turned off by this. */
export const linkDnsText = (name: string) =>
  `DNS: Sieve's encrypted lookups (DNS over HTTPS and DNS over TLS) go through ${name} too, for every app, so the DNS server sees its address. A DNS over QUIC server is asked over this computer's own connection, still encrypted: that server sees this computer's address and every name looked up. The DNS server's own name is looked up from this computer. If you turned DNS encryption off, lookups go out in plain text from this computer, as before.`;

/** What the other device's owner and the sites see. */
export const linkPrivacyText = (name: string) =>
  `Whoever runs ${name} can see where your connections go (site names and addresses, how much and when), never the content of encrypted connections. Unencrypted (http://) pages pass through it as through any network.`;

/** Fail-open, plainly. */
export const LINK_NORMAL_TEXT =
  "Turning this off, pausing or stopping Sieve, a crash or uninstalling Sieve always return this computer to its normal network.";

/** The listen choice: what opens, for whom, and what Sieve does not do. */
export const listenText = (port: number | string) =>
  `Sieve opens TCP port ${port} on the address of the network adapter Windows uses for the internet, only while exiting is on and Sieve routes. Anyone who can reach the port can try to connect; only the paired device's key completes the handshake. Sieve does not change Windows Firewall: allow this port yourself, ideally only from the other device's address.`;

/** The dial choice's hint. */
export const DIAL_HINT_TEXT = "An IP address with its port, such as 203.0.113.20:7443 or [2001:db8::1]:7443. Names are not accepted in this version.";
export const DIAL_FROM_CODE_TEXT = "Leave it empty to use the address the code carries.";

/** The route as a short phrase. */
export function routeWords(route: LinkRoute): string {
  return route.how === "dial" ? `This computer dials ${route.address}` : `The other device dials this computer on port ${route.port}`;
}

/** An IPv4 address in dotted form, each part 0 to 255. */
const isIpv4 = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split(".").every((p) => Number(p) <= 255);

/**
 * Why a typed address cannot be sent, or null. An empty one is allowed only when
 * the code carries one (`optional`). As the engine takes it: an IP address with
 * its port (`203.0.113.20:7443`, `[2001:db8::1]:7443`), never a name.
 */
export function dialAddressProblem(text: string, optional: boolean): string | null {
  const t = text.trim();
  if (t === "") return optional ? null : "Type the other device's address and port.";
  const m = /^(\[([0-9a-fA-F:.]+)\]|[^\s:[\]]+):(\d{1,5})$/.exec(t);
  if (!m) return "Type an address with its port, such as 203.0.113.20:7443.";
  const ip = m[2] ?? m[1];
  const isIp = m[2] !== undefined ? m[2].includes(":") : isIpv4(ip);
  if (!isIp) return "Type an IP address, not a name, such as 203.0.113.20:7443.";
  const port = Number(m[3]);
  return port >= 1 && port <= 65_535 ? null : "The port is a number from 1 to 65535.";
}

/** The typed port, or null when it is not one. */
export function parsePort(text: string): number | null {
  const t = text.trim();
  if (!/^\d{1,5}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= 65_535 ? n : null;
}

/** Why a pasted code cannot be one, or null. Only its size: the engine reads it. Never says the code back. */
export function codeProblem(code: string): string | null {
  const t = code.trim();
  if (t === "") return "Paste the pairing code from the other device.";
  return new TextEncoder().encode(t).length > CODE_MAX ? "That is too long to be a pairing code." : null;
}

/** `text` with every copy of the pairing code taken out, so the code never reaches an error line, whatever the engine said. */
export function withoutCode(text: string, code: string): string {
  const t = code.trim();
  return t === "" ? text : text.split(t).join("(the pairing code)");
}

/** What the app says when an engine without the `link` fact is asked (it is never sent the message). */
export const NO_LINK_TEXT = "this version of Sieve's engine cannot exit through another device";

/** The whole settings with one part changed: `set_link` always carries all of them. */
export const withSetting = <K extends keyof LinkSettings>(s: LinkSettings, key: K, value: LinkSettings[K]): LinkSettings => ({ ...s, [key]: value });

// ---- The log and the issues.

/** How a flow went out while exiting through the other device was on, in words. Never blames the app or Sieve's filtering for the other device's refusal. */
export const EXIT_VIA_TEXT: Readonly<Record<ExitVia, string>> = {
  hub: "Left through the other device",
  direct: "Left directly from this computer",
  stopped: "Stopped: the other device could not be reached",
  refused: "The other device refused it",
  dropped: "Dropped: UDP does not go through the other device",
  unknown: "Went out in a way this version of Sieve cannot name",
};

/** An exit row's reason, in words: the other device's or the engine's own words, as they came. */
export function exitReasonWords(reason: string): string {
  return reason;
}

/**
 * The row's words: a refusal carries the other device's own reason. A row with no
 * target about a way out (through it, or directly) is the engine's own note on
 * no single connection, such as the open connections it ended when the way out
 * changed: its reason is its words.
 */
export function exitWords(via: ExitVia, reason?: string, target?: string): string {
  if ((via === "hub" || via === "direct") && target === undefined && reason) return reason;
  const text = EXIT_VIA_TEXT[via] ?? EXIT_VIA_TEXT.unknown;
  return via === "refused" && reason ? `${text}: ${reason}` : text;
}
