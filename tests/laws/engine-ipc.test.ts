/**
 * Law 9, engine IPC: the app and the engine speak one pipe protocol, owned by
 * the Rust crate `engine/crates/sieve-ipc`. Its fixture
 * `src/data/fixtures/engine-ipc-v3.json` is read by the Rust tests
 * (`cargo test -p sieve-ipc`: every message round trips) and here: the
 * version, the limits and every message type name agree with the crate.
 * Changing a message shape bumps PROTOCOL and the fixture in one commit.
 */
import { describe, expect, it } from "vitest";
import { CAUSE_TEXT, isIntended, SIGNAL_TEXT } from "@/core/issues";
import { REASON_TEXT, RETRY_TEXT } from "@/core/log";
import { MAX_POLICY_BYTES } from "@/core/settings/registry";
import fixture from "@/data/fixtures/engine-ipc-v3.json";
import logFixture from "@/data/fixtures/engine-log-v1.json";
import { BLOCKER_KINDS, CAPTURE_REASONS, CAUSES, CERT_STATES, EXCLUSION_SCOPES, FIREFOX_TRUST, LOG_OUTCOMES, NETWORK_ID_MAX, parseCertStatus, parseEngineLists, parseEngineStatus, parseExclusionsPage, parseHealNotices, parseIssues, parseLogTail, RETRY_HOWS, SIGN_IN_PAUSE_MAX_S, SIGNALS, UPDATE_KINDS } from "@/data/protocol";
import { read } from "./files";

const RUST = read("engine/crates/sieve-ipc/src/lib.rs");

function rustConst(name: string): string {
  const m = RUST.match(new RegExp(`pub const ${name}: [^=]+= ([^;]+);`));
  if (!m) throw new Error(`${name} not found in sieve-ipc`);
  return m[1];
}

function rustNames(name: string): string[] {
  return [...rustConst(name).matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
}

describe("engine IPC law", () => {
  it("fixture version and limits match the crate", () => {
    expect(fixture.protocol).toBe(Number(rustConst("PROTOCOL")));
    expect(fixture.supported).toEqual(JSON.parse(rustConst("SUPPORTED")));
    expect(fixture.maxFrame).toBe(1 << Number(rustConst("MAX_FRAME").replace("1 << ", "")));
    expect(rustConst("MAX_POLICY_BYTES")).toBe("MAX_FRAME / 2");
    expect(fixture.maxPolicyBytes).toBe(fixture.maxFrame / 2);
    expect(MAX_POLICY_BYTES, "what the app measures against is what the engine refuses at").toBe(fixture.maxPolicyBytes);
    expect(fixture.pipe).toBe(rustConst("PIPE_NAME").replace(/^r"|"$/g, ""));
    expect(fixture.flowsBatchMs).toBe(Number(rustConst("FLOWS_BATCH_MS")));
    expect(fixture.flowsPerFrame).toBe(Number(rustConst("FLOWS_PER_FRAME")));
    expect(fixture.logPerFrame).toBe(Number(rustConst("LOG_PER_FRAME")));
    expect(fixture.logUrlMax).toBe(Number(rustConst("LOG_URL_MAX")));
    expect(fixture.logRuleMax).toBe(Number(rustConst("LOG_RULE_MAX")));
  });

  it("the crate's log outcome kinds are the app's, and the app reads every fixture row", () => {
    const crate = (RUST.match(/pub enum LogOutcome \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}(\w+)\b/gm) ?? [];
    const snake = crate.map((v) => v.trim().replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()));
    expect(snake).toEqual([...LOG_OUTCOMES]);
    expect([...new Set(fixture.outcomes.map((o) => o.kind))]).toEqual([...LOG_OUTCOMES]);
    const rows = fixture.engine.find((m) => m.type === "log")!.rows!;
    const tail = parseLogTail({ v: 1, next: rows.length, dropped: 0, rows: rows.map((row, i) => ({ seq: i + 1, row })) });
    expect(tail.skipped).toBe(0);
    expect(tail.rows.map((e) => e.row)).toEqual(rows);
  });

  it("every reason in the fixtures has words in the app", () => {
    const logRows = parseLogTail(logFixture).rows.map((e) => e.row.outcome);
    const reasons = [...fixture.outcomes, ...logRows].flatMap((o) => ("reason" in o && o.reason ? [o.reason] : []));
    expect(reasons.length).toBeGreaterThan(0);
    for (const reason of reasons) expect(REASON_TEXT, reason).toHaveProperty(reason);
  });

  it("every reason the engine's log can say has words in the app, and the row actions' reason is one", () => {
    const book = read("engine/crates/sieve-engine/src/stack/book.rs");
    const body = book.match(/pub fn log_outcome[\s\S]*?\n\}/)?.[0] ?? "";
    const slugs = [...body.matchAll(/passed\("([a-z_]+)"\)/g)].map((m) => m[1]);
    expect(slugs).toEqual(expect.arrayContaining(["no_rule", "exception", "app_off"]));
    for (const slug of slugs) expect(REASON_TEXT, slug).toHaveProperty(slug);
    const log = fixture.engine.find((m) => m.type === "log")! as unknown as { rows: { forwarded?: unknown }[] };
    expect(log.rows.some((r) => r.forwarded !== undefined), "a guest's row is in the fixture").toBe(true);
  });

  it("the app reads the engine's status and every blocker kind the crate declares", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    expect(parseEngineStatus(body)).toEqual(body);
    const crate = (RUST.match(/pub enum Blocker \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}(\w+)\b/gm) ?? [];
    const snake = crate.map((v) => v.trim().replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()));
    expect(snake).toEqual([...BLOCKER_KINDS]);
    expect(fixture.blockers.map((b) => b.kind)).toEqual([...BLOCKER_KINDS]);
    for (const b of fixture.blockers) expect(parseEngineStatus({ ...body, blocker: b }).blocker).toEqual(b);
  });

  it("the app reads a policy holding content, and absent stays absent", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    const policy = Object.fromEntries(Object.entries(fixture.policyWithContent).filter(([k]) => k !== "type"));
    expect(parseEngineStatus({ ...body, policy }).policy).toEqual(policy);
    expect(parseEngineStatus(body).policy).not.toHaveProperty("content");
    expect(() => parseEngineStatus({ ...body, policy: { ...policy, content: 1 } })).toThrow(/policy\.content/);
  });

  it("the app reads the user's plain DNS choice and the unreachable notice; absent is encrypted and nothing to say", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    const policy = Object.fromEntries(Object.entries(fixture.policyWithPlainDns).filter(([k]) => k !== "type"));
    expect(parseEngineStatus({ ...body, policy }).policy).toEqual(policy);
    expect(parseEngineStatus(body).policy).not.toHaveProperty("plain_dns");
    expect(() => parseEngineStatus({ ...body, policy: { ...policy, plain_dns: "yes" } })).toThrow(/policy\.plain_dns/);
    expect(parseEngineStatus({ ...body, dns_unreachable: true }).dns_unreachable).toBe(true);
    expect(parseEngineStatus(body)).not.toHaveProperty("dns_unreachable");
    expect(parseEngineStatus({ ...body, dns_unreachable: 1 }), "a notice never refuses the Status").not.toHaveProperty("dns_unreachable");
    expect(RUST).toMatch(/skip_serializing_if = "std::ops::Not::not"\)\]\s*pub plain_dns: bool/);
    expect(RUST).toMatch(/skip_serializing_if = "std::ops::Not::not"\)\]\s*pub dns_unreachable: bool/);
  });

  it("the app reads the capture switch and every capture state; absent is on and nothing to say", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    const policy = Object.fromEntries(Object.entries(fixture.policyWithoutDnsCapture).filter(([k]) => k !== "type"));
    expect(parseEngineStatus({ ...body, policy }).policy).toEqual(policy);
    expect(parseEngineStatus(body).policy, "an older engine: on").not.toHaveProperty("skip_dns_capture");
    expect(() => parseEngineStatus({ ...body, policy: { ...policy, skip_dns_capture: "no" } })).toThrow(/policy\.skip_dns_capture/);
    expect(RUST).toMatch(/skip_serializing_if = "std::ops::Not::not"\)\]\s*pub skip_dns_capture: bool/);
    for (const state of fixture.dnsCaptureStates) expect(parseEngineStatus({ ...body, dns_capture: state }).dns_capture).toEqual(state);
    expect(parseEngineStatus(body), "an older engine says nothing").not.toHaveProperty("dns_capture");
    for (const odd of [1, { state: "maybe" }, { state: "not_caught", reason: "new_reason", detail: "x" }, { state: "not_caught", reason: "tie" }]) {
      expect(parseEngineStatus({ ...body, dns_capture: odd }), `a notice never refuses the Status: ${JSON.stringify(odd)}`).not.toHaveProperty("dns_capture");
    }
    const crate = (RUST.match(/pub enum CaptureReason \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}(\w+)\b/gm) ?? [];
    expect(crate.map((v) => v.trim().replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()))).toEqual([...CAPTURE_REASONS]);
    expect(fixture.dnsCaptureStates.flatMap((s) => ("reason" in s ? [s.reason] : []))).toEqual([...CAPTURE_REASONS]);
  });

  it("the app reads the Wi-Fi sign-in fact; absent, odd or from an older engine is nothing to say; its limits are the crate's", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    expect(parseEngineStatus(body), "an older engine says nothing").not.toHaveProperty("wifi_sign_in");
    for (const state of fixture.wifiSignInStates) expect(parseEngineStatus({ ...body, wifi_sign_in: state }).wifi_sign_in).toEqual(state);
    expect(parseEngineStatus({ ...body, wifi_sign_in: { network: "n", paused_left_s: 9, later: true } }).wifi_sign_in, "a later engine's field is ignored").toEqual({ network: "n", paused_left_s: 9 });
    for (const odd of [1, {}, { network: "" }, { network: 7 }, { network: "x".repeat(NETWORK_ID_MAX + 1) }, { network: "n", paused_left_s: -1 }, { network: "n", paused_left_s: "soon" }]) {
      expect(parseEngineStatus({ ...body, wifi_sign_in: odd }), `a notice never refuses the Status: ${JSON.stringify(odd)}`).not.toHaveProperty("wifi_sign_in");
    }
    expect(parseEngineStatus({ ...body, wifi_sign_in: { network: "n", paused_left_s: 10_000 } }).wifi_sign_in?.paused_left_s, "never past the cap").toBe(SIGN_IN_PAUSE_MAX_S);
    expect(rustConst("SIGN_IN_PAUSE_MAX_S")).toBe("15 * 60");
    expect(Number(rustConst("NETWORK_ID_MAX"))).toBe(NETWORK_ID_MAX);
    expect(RUST).toMatch(/skip_serializing_if = "Option::is_none"\)\]\s*pub wifi_sign_in: Option<WifiSignIn>/);
    expect(fixture.client.filter((m) => m.type === "pause_dns_capture" || m.type === "resume_dns_capture")).toEqual([
      { type: "pause_dns_capture", network: fixture.wifiSignInStates[0].network },
      { type: "resume_dns_capture" },
    ]);
  });

  it("the app reads every certificate status, and its enums are the crate's", () => {
    const message = fixture.engine.find((m) => m.type === "cert_status")!;
    const body = Object.fromEntries(Object.entries(message).filter(([k]) => k !== "type"));
    expect(parseCertStatus(body)).toEqual(body);
    for (const example of Object.values(fixture.certStatuses)) expect(parseCertStatus(example)).toEqual(example);
    const variants = (name: string) =>
      ((RUST.match(new RegExp(`pub enum ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1] ?? "").match(/^\s{4}([A-Z]\w+),/gm) ?? []).map((v) =>
        v.trim().replace(",", "").replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()),
      );
    expect(variants("CertState")).toEqual([...CERT_STATES]);
    expect(variants("FirefoxTrust")).toEqual([...FIREFOX_TRUST]);
  });

  it("the app reads every update state the crate declares, unchanged", () => {
    const status = fixture.engine.find((m) => m.type === "status")!;
    const body = Object.fromEntries(Object.entries(status).filter(([k]) => k !== "type"));
    const crate = (RUST.match(/pub enum UpdateStatus \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}(?!#|\/)(\w+)\b/gm) ?? [];
    const snake = crate.map((v) => v.trim().replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()));
    expect(snake).toEqual([...UPDATE_KINDS]);
    expect(fixture.updates.map((u) => u.kind)).toEqual([...UPDATE_KINDS]);
    for (const u of fixture.updates) expect(parseEngineStatus({ ...body, update: u }).update).toEqual(u);
  });

  it("the app reads what is not decrypted and the notices, and the scope's names are the crate's", () => {
    const body = (type: string) => Object.fromEntries(Object.entries(fixture.engine.find((m) => m.type === type)!).filter(([k]) => k !== "type"));
    expect(parseExclusionsPage(body("exclusions"))).toEqual({ ...body("exclusions"), skipped: 0 });
    expect(parseHealNotices(body("heal_notices"))).toEqual(body("heal_notices"));
    const scopes = ((RUST.match(/pub enum ExclusionScope \{([\s\S]*?)\n\}/)?.[1] ?? "").match(/^\s{4}([A-Z]\w+),/gm) ?? []).map((v) => v.trim().replace(",", "").toLowerCase());
    expect(scopes).toEqual([...EXCLUSION_SCOPES]);
  });

  it("a bad exclusion row or notice is left out and counted; a wrong shape throws", () => {
    const body = Object.fromEntries(Object.entries(fixture.engine.find((m) => m.type === "exclusions")!).filter(([k]) => k !== "type"));
    const page = parseExclusionsPage({ ...body, rows: [null, 7, { line: "" , reason: "x" }, { reason: "x" }, { line: "a.example", reason: "user" }] });
    expect(page.skipped).toBe(4);
    expect(page.rows).toEqual([{ line: "a.example", apps: [], reason: "user", created_ms: null, retries: 0 }]);
    expect(() => parseExclusionsPage({ ...body, rows: null })).toThrow(/rows/);
    expect(() => parseExclusionsPage({ ...body, scope: "some" })).toThrow(/scope/);
    expect(() => parseExclusionsPage(null)).toThrow();
    expect(() => parseHealNotices({ revision: 1, exclusions_revision: 1, notices: [] }), "a run names the cursor's meaning").toThrow(/heal\.run/);
    const notices = parseHealNotices({ run: 1, revision: 1, exclusions_revision: 1, notices: [null, { id: 1 }, { id: 1, session: 1, exe: "a.exe", hosts: [], total: 0, rev: 1 }, { id: 2, session: 1, exe: "a.exe", hosts: ["a.example"], total: 0, rev: 1 }] });
    expect(notices.notices).toEqual([{ id: 2, session: 1, exe: "a.exe", hosts: ["a.example"], total: 1, rev: 1 }]);
    expect(() => parseHealNotices({ revision: 1, exclusions_revision: 1 })).toThrow(/notices/);
  });

  it("fixture names every message type of the crate, in order", () => {
    expect(fixture.client.map((m) => m.type)).toEqual(rustNames("CLIENT_TYPES"));
    expect(fixture.engine.map((m) => m.type)).toEqual(rustNames("ENGINE_TYPES"));
  });

  it("the app reads the list report; a partial row degrades, a wrong shape throws", () => {
    const body = Object.fromEntries(Object.entries(fixture.engine.find((m) => m.type === "lists")!).filter(([k]) => k !== "type"));
    expect(parseEngineLists(body)).toEqual(body);
    expect(parseEngineLists({ lists: [{ id: "x", enabled: false }] })).toEqual({
      lists: [{ id: "x", enabled: false, fetched_at_ms: null, refresh_s: null, last_error: null, network: 0, cosmetic: 0, skipped: 0, skip_reasons: {}, skipped_exceptions: [], skipped_exceptions_total: 0 }],
      compile_ms: null,
    });
    expect(() => parseEngineLists({})).toThrow(/lists/);
    expect(() => parseEngineLists(null)).toThrow();
    expect(() => parseEngineLists({ lists: [{ enabled: true }] })).toThrow(/id/);
    expect(() => parseEngineLists({ lists: [{ id: "x", enabled: true, network: -1 }] })).toThrow(/network/);
    expect(() => parseEngineLists({ lists: [{ id: "x", enabled: true, skipped_exceptions: [1] }] })).toThrow(/skipped_exceptions/);
  });

  it("a VM row's key is the crate's vm_key, and a flow is a process's or a guest's, never both", () => {
    const body = RUST.match(/pub fn vm_key\(vm: Option<&str>\) -> String \{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(body).toContain('format!("vm:{}"');
    expect(body).toContain("to_lowercase");
    expect(rustConst("VM_UNIDENTIFIED")).toBe('"unidentified"');
    const status = fixture.engine.find((m) => m.type === "status")! as unknown as { guests: { key: string; vm: string | null }[] };
    expect(status.guests.length).toBeGreaterThan(1);
    for (const g of status.guests) expect(g.key).toBe(`vm:${(g.vm ?? "unidentified").toLowerCase()}`);
    const flows = fixture.engine.find((m) => m.type === "flows")! as unknown as { flows: { pid: number | null; forwarded: unknown }[] };
    for (const f of flows.flows) expect(f.pid === null || f.forwarded === null).toBe(true);
  });

  it("the app's signals, causes and retries are the crate's, each has words, and the app reads the issues fixture", () => {
    const variants = (name: string) =>
      ((RUST.match(new RegExp(`pub enum ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1] ?? "").match(/^\s{4}([A-Z]\w+),/gm) ?? []).map((v) =>
        v.trim().replace(",", "").replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()),
      );
    expect(variants("Signal")).toEqual([...SIGNALS]);
    expect(variants("Cause")).toEqual([...CAUSES]);
    expect(variants("RetryHow")).toEqual([...RETRY_HOWS]);
    for (const s of SIGNALS) expect(SIGNAL_TEXT[s], s).toBeTruthy();
    for (const c of CAUSES) expect(CAUSE_TEXT[c], c).toBeTruthy();
    for (const h of RETRY_HOWS) expect(RETRY_TEXT[h], h).toBeTruthy();
    const intended = RUST.match(/pub fn intended\(self\) -> bool \{([\s\S]*?)\n    \}/)?.[1] ?? "";
    const crateIntended = [...intended.matchAll(/Self::(\w+)/g)].map((m) => m[1].replace(/[A-Z]/g, (c, i) => (i ? "_" : "") + c.toLowerCase()));
    expect(SIGNALS.filter((s) => isIntended({ signal: s }))).toEqual(crateIntended);
    const body = Object.fromEntries(Object.entries(fixture.engine.find((m) => m.type === "issues")!).filter(([k]) => k !== "type"));
    expect(parseIssues(body)).toEqual(body);
  });

  it("no message can sign, export or mint", () => {
    for (const name of [...rustNames("CLIENT_TYPES"), ...rustNames("ENGINE_TYPES")]) {
      expect(name).not.toMatch(/sign|export|mint|key/);
    }
  });
});
