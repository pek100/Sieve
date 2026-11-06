import { describe, expect, it } from "vitest";
import table from "@/data/fixtures/upstream-grammar.json";
import { MAX_UPSTREAMS, UPSTREAM_KINDS, composeUpstream, parseUpstream, upstreamIdentity, upstreamReadback, type UpstreamKind } from "./upstream";

const address = (kind: UpstreamKind, typed: string) => composeUpstream(kind, typed)?.address ?? null;

describe("parseUpstream: the three encrypted kinds", () => {
  it("reads DoH, with and without a port", () => {
    expect(parseUpstream("https://cloudflare-dns.com/dns-query")).toEqual({ kind: "doh", host: "cloudflare-dns.com", port: null, path: "/dns-query" });
    expect(parseUpstream("https://192.0.2.1:8443/dns-query")).toEqual({ kind: "doh", host: "192.0.2.1", port: 8443, path: "/dns-query" });
    expect(parseUpstream("https://[2001:db8::1]/q")).toEqual({ kind: "doh", host: "[2001:db8::1]", port: null, path: "/q" });
  });

  it("reads DoT and DoQ, with and without a port", () => {
    expect(parseUpstream("tls://dns.example")).toEqual({ kind: "dot", host: "dns.example", port: null, path: null });
    expect(parseUpstream("tls://dns.example:853")).toEqual({ kind: "dot", host: "dns.example", port: 853, path: null });
    expect(parseUpstream("quic://dns.example")).toEqual({ kind: "doq", host: "dns.example", port: null, path: null });
    expect(parseUpstream("quic://[2001:db8::1]:853")).toEqual({ kind: "doq", host: "[2001:db8::1]", port: 853, path: null });
  });

  it("refuses bare addresses: the engine sends no plain DNS", () => {
    for (const bad of ["1.1.1.1", "9.9.9.9:53", "2620:fe::fe", "[2606:4700::1111]:53", "dns.example"]) expect(parseUpstream(bad), bad).toBeNull();
  });

  it("refuses other schemes, an empty host, whitespace and userinfo", () => {
    for (const bad of [
      "http://dns.example/dns-query",
      "ftp://dns.example",
      "https://",
      "https:///dns-query",
      "tls://",
      "quic://:853",
      " tls://dns.example",
      "tls://dns.example ",
      "https://dns.example/dns query",
      "https://user:pw@dns.example/dns-query",
      "tls://user@dns.example",
      "",
    ]) {
      expect(parseUpstream(bad), bad).toBeNull();
    }
  });

  it("refuses a port out of range, a path or query on DoT and DoQ, and a fragment", () => {
    for (const bad of ["tls://dns.example:0", "tls://dns.example:65536", "tls://dns.example/x", "quic://dns.example/x", "quic://dns.example?x=1", "https://dns.example/q#f"]) {
      expect(parseUpstream(bad), bad).toBeNull();
    }
  });

  it("keeps a DoH query in the request target, and reads a bare host as the path /, as the engine does", () => {
    expect(parseUpstream("https://dns.example/q?a=1")).toEqual({ kind: "doh", host: "dns.example", port: null, path: "/q?a=1" });
    expect(parseUpstream("https://dns.example")).toEqual({ kind: "doh", host: "dns.example", port: null, path: "/" });
    expect(parseUpstream("tls://dns.example/")).toEqual({ kind: "dot", host: "dns.example", port: null, path: null });
  });
});

describe("composeUpstream", () => {
  it.each([
    ["doh", "dns.example", "https://dns.example/dns-query"],
    ["doh", "dns.example:8443", "https://dns.example:8443/dns-query"],
    ["doh", "192.0.2.1", "https://192.0.2.1/dns-query"],
    ["doh", "2001:db8::1", "https://[2001:db8::1]/dns-query"],
    ["doh", "[2001:db8::1]:8443", "https://[2001:db8::1]:8443/dns-query"],
    ["doh", "dns.example/q", "https://dns.example/q"],
    ["doh", "dns.example/q?profile=1", "https://dns.example/q?profile=1"],
    ["doh", "  dns.example ", "https://dns.example/dns-query"],
    ["dot", "dns.example", "tls://dns.example"],
    ["dot", "dns.example:8853", "tls://dns.example:8853"],
    ["dot", "192.0.2.1", "tls://192.0.2.1"],
    ["dot", "2001:db8::1", "tls://[2001:db8::1]"],
    ["doq", "dns.example", "quic://dns.example"],
    ["doq", "dns.example:8853", "quic://dns.example:8853"],
    ["doq", "192.0.2.1", "quic://192.0.2.1"],
    ["doq", "2001:db8::1", "quic://[2001:db8::1]"],
  ] as const)("%s and %j become %s, which the grammar accepts", (kind, typed, want) => {
    expect(address(kind, typed)).toBe(want);
    expect(parseUpstream(want)?.kind).toBe(kind);
  });

  it("a full URL stays as written and reports its own kind, whatever is selected", () => {
    for (const raw of table.accept) {
      for (const kind of UPSTREAM_KINDS) {
        const composed = composeUpstream(kind, raw);
        expect(composed?.address, raw).toBe(raw);
        expect(composed?.upstream.kind, raw).toBe(parseUpstream(raw)?.kind);
      }
    }
  });

  it("every refused form that says its scheme is refused under every kind", () => {
    const written = table.refuse.filter((raw) => /^\s*[a-z]+:/.test(raw));
    expect(written.length).toBeGreaterThan(20);
    for (const raw of written) for (const kind of UPSTREAM_KINDS) expect(composeUpstream(kind, raw), raw).toBeNull();
  });

  it("nothing typed and a host the grammar refuses are refused", () => {
    for (const typed of ["", "   ", "a!b.example", "a..b.example", "user@dns.example", "dns example"]) expect(composeUpstream("dot", typed), typed).toBeNull();
    expect(composeUpstream("dot", "dns.example/x"), "DoT takes no path").toBeNull();
  });
});

describe("upstreamIdentity", () => {
  const identity = (raw: string) => upstreamIdentity(parseUpstream(raw)!);

  it("reads two spellings of one upstream as one, as the engine does", () => {
    expect(identity("tls://DNS.example")).toBe(identity("tls://dns.example:853"));
    expect(identity("tls://dns.example.")).toBe(identity("tls://dns.example"));
    expect(identity("https://dns.example:443/q")).toBe(identity("https://DNS.example/q"));
  });

  it("keeps apart what differs", () => {
    expect(identity("tls://dns.example")).not.toBe(identity("quic://dns.example"));
    expect(identity("tls://dns.example")).not.toBe(identity("tls://dns.example:8853"));
    expect(identity("https://dns.example/a")).not.toBe(identity("https://dns.example/b"));
  });
});

describe("upstreamReadback", () => {
  const list = ["tls://a.example", "tls://b.example"];

  it("says nothing while the engine cannot be asked, or holds no list", () => {
    expect(upstreamReadback(list, null)).toBeNull();
    expect(upstreamReadback(list, undefined)).toBeNull();
    expect(upstreamReadback(list, [])).toBeNull();
  });

  it("says the list is in use only for the same list in the same order", () => {
    expect(upstreamReadback(list, list)).toBe("The engine uses this list.");
    expect(upstreamReadback(list, [...list].reverse())).toBe("The engine still uses: tls://b.example, tls://a.example.");
    expect(upstreamReadback(list, list.slice(0, 1))).toBe("The engine still uses: tls://a.example.");
  });
});

it("the limit is the table's", () => {
  expect(MAX_UPSTREAMS).toBe(table.max);
  expect(MAX_UPSTREAMS).toBeGreaterThan(0);
});
