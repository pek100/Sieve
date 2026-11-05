import { describe, expect, it } from "vitest";
import { parseUpstream } from "./upstream";

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

  it("refuses a port out of range, a path on DoT and DoQ, and a DoH form with no path or with a query", () => {
    for (const bad of ["tls://dns.example:0", "tls://dns.example:65536", "tls://dns.example/x", "quic://dns.example/x", "https://dns.example", "https://dns.example/q?a=1", "https://dns.example/q#f"]) {
      expect(parseUpstream(bad), bad).toBeNull();
    }
  });
});
