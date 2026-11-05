/**
 * Law 13, trust writes (docs/plans/2026-10-17-https-filtering.md, 1.5, 2.2 to
 * 2.4, 7.3). A trusted root is the most dangerous thing Sieve can leave on a
 * machine, so what may write one is pinned by name:
 *
 * - The CNG key writes, the root store writes and the registry writes of the
 *   Firefox policy are named only under `ca/win/`; the app names none of them.
 * - The real seams (`CngKeyStore`, `WindowsRootStore`, `RegistryFirefoxPolicy`)
 *   are named only there and in `service/runner.rs` and `service/scm.rs`, the
 *   service and its verbs, so no test can reach a real store: `service::scm`'s
 *   tests call nothing that builds one, and everything else takes fakes.
 * - Removal goes by recorded thumbprint: nothing in `ca/` can find a
 *   certificate by subject.
 * - No site name in `ca/` (plan 7.2).
 */
import { describe, expect, it } from "vitest";
import { hits, read, walk } from "./files";

const ENGINE = "engine/crates";
const CA = "engine/crates/sieve-engine/src/ca/";
const CA_WIN = `${CA}win/`;
const SERVICE_SIDE = ["engine/crates/sieve-engine/src/service/runner.rs", "engine/crates/sieve-engine/src/service/scm.rs"];

const TRUST_WRITES = /CertAddCertificateContextToStore|CertDeleteCertificateFromStore|NCryptCreatePersistedKey|NCryptDeleteKey|RegSetValue|RegDeleteValue/;
const REAL_SEAMS = /\b(CngKeyStore|WindowsRootStore|RegistryFirefoxPolicy)\b/;
/** A host name a person would recognize: a label and a public suffix (the reserved `.example` is what tests use). */
const SITE_NAME = /\b[a-z0-9-]+\.(com|org|net|io|gov|edu|co)\b/i;

const engineSources = () => walk(ENGINE, [".rs"]);
const appSources = () => [...walk("src", [".ts", ".tsx"]), ...walk("src-tauri/src", [".rs"])];

describe("trust write law", () => {
  it("every key, store and registry write is under ca/win", () => {
    const found = engineSources().flatMap((f) => hits(f, TRUST_WRITES));
    const outside = found.filter((h) => !h.startsWith(CA_WIN));
    expect(outside).toEqual([]);
    const names = found.join("\n");
    for (const name of ["CertAddCertificateContextToStore", "CertDeleteCertificateFromStore", "NCryptCreatePersistedKey", "NCryptDeleteKey", "RegSetValue", "RegDeleteValue"]) {
      expect(names, `the law still sees ${name}`).toContain(name);
    }
  });

  it("the app names none of them", () => {
    expect(appSources().flatMap((f) => hits(f, TRUST_WRITES))).toEqual([]);
  });

  it("the real seams are named only by themselves and the service's two files", () => {
    const named = engineSources().filter((f) => REAL_SEAMS.test(read(f)));
    const outside = named.filter((f) => !f.startsWith(CA_WIN) && !SERVICE_SIDE.includes(f));
    expect(outside).toEqual([]);
    for (const f of SERVICE_SIDE) expect(named, f).toContain(f);
  });

  it("no test module in the service's files builds a real seam", () => {
    for (const f of SERVICE_SIDE) {
      const tests = read(f).split("#[cfg(test)]")[1] ?? "";
      expect(tests, f).not.toMatch(REAL_SEAMS);
      // The verbs that use them are not called by a test either.
      expect(tests, f).not.toMatch(/\b(trust|ca_keys|uninstall|purge_ca_keys|real_ca)\(\)/);
    }
  });

  it("a certificate is found by SHA-1 hash, never by subject", () => {
    const sources = walk(CA, [".rs"]);
    expect(sources.flatMap((f) => hits(f, /CERT_FIND_SUBJECT|CERT_FIND_ISSUER|CERT_FIND_ANY|CertEnumCertificatesInStore/))).toEqual([]);
    expect(read(`${CA_WIN}store.rs`)).toContain("CERT_FIND_SHA1_HASH");
  });

  it("the key cannot leave: non-exportable, SYSTEM only, the public blob alone is exported", () => {
    const cng = read(`${CA_WIN}cng.rs`);
    expect(cng).toContain('KEY_SDDL: &str = "D:P(A;;GA;;;SY)"');
    expect(cng).toContain("EXPORT_NONE: u32 = 0");
    expect(cng).not.toMatch(/NCRYPT_ALLOW_\w*EXPORT|BCRYPT_ECCPRIVATE_BLOB|PKCS8_PRIVATE/);
    expect(cng.indexOf("NCRYPT_SECURITY_DESCR_PROPERTY, bytes")).toBeLessThan(cng.indexOf("NCryptFinalizeKey(key"));
  });

  it("no site name in ca/", () => {
    expect(walk(CA, [".rs"]).flatMap((f) => hits(f, SITE_NAME))).toEqual([]);
  });

  it("the uninstall verb keeps its order: trust and keys before the service goes", () => {
    const scm = read(SERVICE_SIDE[1]).split("const UNINSTALL")[1] ?? "";
    const order = ["routes", "stop", "trust", "ca keys", "delete service", "program data"].map((s) => scm.indexOf(`("${s}", `));
    expect(order.every((at) => at >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it("the verb's service deletion goes through the gate that keeps it for the rerun", () => {
    const scm = read(SERVICE_SIDE[1]);
    expect(scm).toContain('("delete service", delete_service)');
    expect(scm).toContain("removal::delete_service_once_clear(&dir, hold_for_rerun, delete)");
    expect(scm).toContain("removal::purge_through_service(&dir, ");
  });
});
