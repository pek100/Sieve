import { describe, expect, it } from "vitest";
import { createPassedChecks } from "@/core/checks";
import { ENGINE_POLL_MS, ENGINE_SWITCH, HTTPS_SWITCH, engineLockReason, enginePhase, engineUpdate } from "@/core/engine";
import { createNoticeBus } from "@/core/notices";
import { MAX_POLICY_BYTES, type SettingKey } from "@/core/settings/registry";
import { GLOBAL_SWITCH } from "@/core/policy";
import { createStore } from "@/core/store";
import { CRASH_LOOP_BANNER, createEngineController } from "./engine-controller";
import { createMockEngine, MOCK_ADGUARD_ERROR, MOCK_CERT_ERROR, MOCK_ENGINE_ERROR, MOCK_HTTPS_OFF, type CertScenario, type EngineScenario } from "./engine-mock";
import type { EngineSource } from "./engine-source";
import { createMockFilterLists } from "./filter-lists-mock";
import type { FilterListSource } from "./filter-lists-source";
import type { Clock } from "./poller";
import type { EngineDnsUpstreams, EnginePolicy, EngineProbe } from "./protocol";
import { createSettingsStore, memoryBackend, type SettingsBackend } from "./settings-store";

const SWITCH = ENGINE_SWITCH as SettingKey;

/** What the settings' defaults ask of the engine, at a revision and switch. */
const policy = (revision: number, engine: boolean): EnginePolicy => ({ revision, engine, sieving: true, off_apps: [], lists: null, domain_lists: [], https: false, user_rules: [], exclusions: [] });

function fakeClock() {
  let now = 0;
  let seq = 0;
  const timers = new Map<number, { at: number; fn: () => void }>();
  const clock: Clock = {
    now: () => now,
    setTimeout: (fn, ms) => {
      const id = ++seq;
      timers.set(id, { at: now + ms, fn });
      return id;
    },
    clearTimeout: (h) => void timers.delete(h as number),
  };
  const flush = async () => {
    for (let i = 0; i < 5; i++) await new Promise<void>((r) => setTimeout(r, 0));
  };
  return {
    clock,
    flush,
    pending: () => timers.size,
    async advance(ms: number) {
      const target = now + ms;
      for (;;) {
        const due = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await flush();
      }
      now = target;
    },
  };
}

/** The mock engine, with its scenario changeable between probes and every call recorded. */
function fakeEngine(start: EngineScenario) {
  let mock = createMockEngine(start);
  const policies: EnginePolicy[] = [];
  const upstreams: EngineDnsUpstreams[] = [];
  let probes = 0;
  let certReads = 0;
  let rowReads = 0;
  let noticeReads = 0;
  const source: EngineSource = {
    kind: "mock",
    probe: () => {
      probes++;
      return mock.probe();
    },
    setPolicy: (p) => {
      policies.push(p);
      return mock.setPolicy(p);
    },
    lists: () => mock.lists(),
    listsRefresh: () => mock.listsRefresh(),
    dnsUpstreams: () => mock.dnsUpstreams(),
    setDnsUpstreams: (l) => {
      upstreams.push(l);
      return mock.setDnsUpstreams(l);
    },
    requestUpdate: () => mock.requestUpdate(),
    stopAdguard: () => mock.stopAdguard(),
    startAdguard: () => mock.startAdguard(),
    logTail: (since) => mock.logTail(since),
    certStatus: () => {
      certReads++;
      return mock.certStatus();
    },
    installRoot: () => mock.installRoot(),
    exclusions: (after) => {
      rowReads++;
      return mock.exclusions(after);
    },
    tryDecryptAgain: (line, app) => mock.tryDecryptAgain(line, app),
    healNotices: (after) => {
      noticeReads++;
      return mock.healNotices(after);
    },
  };
  return {
    source,
    set: (s: EngineScenario) => void (mock = createMockEngine(s)),
    setCert: (c: CertScenario) => void (mock = createMockEngine(start, { cert: c })),
    holdHttps: () => void (mock = createMockEngine(start, { heal: true })),
    probes: () => probes,
    certReads: () => certReads,
    rowReads: () => rowReads,
    noticeReads: () => noticeReads,
    policies,
    upstreams,
  };
}

describe("engine controller, what is not decrypted", () => {
  /** An engine holding HTTPS on, one probe in. */
  async function holdingOff() {
    const s = setup("idle");
    await s.fc.flush();
    s.fake.holdHttps();
    return s;
  }
  async function holding() {
    const s = await holdingOff();
    await s.fc.advance(ENGINE_POLL_MS);
    return s;
  }
  const slice = (s: ReturnType<typeof setup>) => s.store.getState().engine;

  it("reads nothing while HTTPS is not in force", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.probes()).toBeGreaterThan(0);
    expect([s.fake.noticeReads(), s.fake.rowReads()]).toEqual([0, 0]);
    expect(slice(s).exclusions ?? null).toBeNull();
    s.undo();
  });

  it("reads the rows once, and again only when their revision moved", async () => {
    const s = await holding();
    expect(s.fake.rowReads()).toBe(1);
    expect(slice(s).exclusions?.rows.map((r) => r.reason)).toEqual(["list:sensitive", "auto:pinning", "auto:client-cert", "auto:ev"]);
    expect(slice(s).exclusions?.scope).toBe("browsers");
    const notices = s.fake.noticeReads();
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.noticeReads(), "notices are read every probe").toBeGreaterThan(notices);
    expect(s.fake.rowReads(), "the rows are not").toBe(1);
    await s.controller.tryDecryptAgain('"pin.example"', "client.exe");
    expect(slice(s).exclusions?.rows.map((r) => r.reason)).toEqual(["list:sensitive", "auto:client-cert", "auto:ev"]);
    const healed = slice(s).exclusions?.revision;
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.rowReads(), "the answer carried the revision").toBe(1);
    expect(slice(s).exclusions?.revision).toBe(healed);
    s.undo();
  });

  it("walks every page", async () => {
    const s = await holdingOff();
    const row = (i: number) => ({ line: `h${i}.example`, apps: [], reason: "list:x", created_ms: null, retries: 0 });
    const page = (rows: number[], next: number | null) => ({ revision: 9, rows: rows.map(row), total: 3, next, scope: "all" as const, browsers: [], skipped: 1 });
    s.fake.source.exclusions = async (after) => (after === 0 ? page([0, 1], 2) : page([2], null));
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusions?.rows.map((r) => r.line)).toEqual(["h0.example", "h1.example", "h2.example"]);
    expect(slice(s).exclusions?.skipped).toBe(2);
    s.undo();
  });

  it("a cursor that does not move on is an error, not a hang", async () => {
    const s = await holdingOff();
    s.fake.source.exclusions = async () => ({ revision: 9, rows: [], total: 3, next: 1, scope: "all", browsers: [], skipped: 0 });
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusionsError).toMatch(/does not move on/);
    s.undo();
  });

  it("a failed read keeps the rows and says why; the next good one clears it", async () => {
    const s = await holding();
    const rows = slice(s).exclusions?.rows;
    const works = s.fake.source.healNotices;
    s.fake.source.healNotices = async () => {
      throw new Error("the pipe closed");
    };
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusionsError).toBe("the pipe closed");
    expect(slice(s).exclusions?.rows).toBe(rows);
    s.fake.source.healNotices = works;
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusionsError).toBeNull();
    s.undo();
  });

  it("an old engine answering an error degrades the same way", async () => {
    const s = await holdingOff();
    s.fake.source.healNotices = async () => {
      throw new Error("unknown variant `heal_notices`");
    };
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusionsError).toMatch(/unknown variant/);
    expect(slice(s).exclusions ?? null).toBeNull();
    s.undo();
  });

  it("HTTPS going out of force clears what it said", async () => {
    const s = await holding();
    expect(slice(s).healNotices?.length).toBe(1);
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).exclusions).toBeNull();
    expect(slice(s).healNotices).toEqual([]);
    s.undo();
  });

  it("a group's new revision replaces it in the slice, and a new engine run is a new group", async () => {
    const s = await holding();
    expect(slice(s).healNotices?.map((n) => [n.key, n.total])).toEqual([["0:1", 1]]);
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).healNotices?.map((n) => [n.key, n.total])).toEqual([["0:1", 2]]);
    s.fake.holdHttps();
    await s.fc.advance(ENGINE_POLL_MS);
    expect(slice(s).healNotices?.map((n) => n.key)).toEqual(["0:1", "1:1"]);
    s.undo();
  });

  it("a refused try again is said, and the rows stand", async () => {
    const s = await holding();
    s.fake.source.tryDecryptAgain = async () => {
      throw new Error("not an exclusion line");
    };
    await s.controller.tryDecryptAgain("bad line", null);
    expect(slice(s).exclusionsActionError).toMatch(/could not try that again.*not an exclusion line/);
    expect(slice(s).exclusions?.rows).toHaveLength(4);
    s.undo();
  });
});

function setup(start: EngineScenario, backend: SettingsBackend = memoryBackend(), filterLists: FilterListSource = createMockFilterLists()) {
  const fc = fakeClock();
  const store = createStore();
  const fake = fakeEngine(start);
  const settings = createSettingsStore(backend);
  const checks = createPassedChecks();
  const notices = createNoticeBus();
  const controller = createEngineController({ engine: fake.source, store, clock: fc.clock, settings, checks, notices, filterLists });
  const undo = controller.bind();
  const phase = () => enginePhase(store.getState().engine);
  return { fc, store, fake, settings, checks, notices, controller, undo, phase };
}

describe("engine controller, updates", () => {
  const banners = (s: ReturnType<typeof setup>) => s.notices.list().filter((n) => n.surface === "banner").map((n) => n.text);
  const update = (s: ReturnType<typeof setup>) => engineUpdate(s.store.getState().engine);

  it("the update button sends the one request and the answer shows at once", async () => {
    const s = setup("update_available");
    await s.fc.flush();
    await s.controller.requestUpdate();
    expect(update(s)).toEqual({ kind: "applying", version: "0.2.0" });
    expect(s.store.getState().engine.actionError).toBeNull();
    s.undo();
  });

  it("a request the engine refuses is said, and the state stands", async () => {
    const s = setup("update_current");
    await s.fc.flush();
    s.fake.source.requestUpdate = async () => {
      throw new Error("an update check ran moments ago; try again in a few minutes");
    };
    await s.controller.requestUpdate();
    expect(s.store.getState().engine.actionError).toMatch(/did not go through.*moments ago/);
    expect(s.store.getState().engine.requestingUpdate).toBe(false);
    expect(update(s)).toEqual({ kind: "current" });
    s.undo();
  });

  it("a second click while the first is in flight sends nothing", async () => {
    const s = setup("update_available");
    await s.fc.flush();
    let asked = 0;
    let finish = () => {};
    const status = await s.fake.source.requestUpdate();
    s.fake.source.requestUpdate = () => {
      asked++;
      return new Promise((resolve) => {
        finish = () => resolve(status);
      });
    };
    const first = s.controller.requestUpdate();
    await s.controller.requestUpdate();
    finish();
    await first;
    expect(asked).toBe(1);
    s.undo();
  });

  it("one Home banner for an offered release, replaced when it is rolled back, gone when it is over", async () => {
    const s = setup("update_available");
    await s.fc.flush();
    expect(banners(s)).toEqual(["Sieve 0.2.0 is available. Install it in Settings > Filtering."]);
    await s.fc.advance(ENGINE_POLL_MS);
    expect(banners(s)).toHaveLength(1);
    s.fake.set("update_rolled_back");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(banners(s)).toEqual(["Sieve 0.2.0 did not start, so the previous version is back. Your network works as usual."]);
    s.fake.set("update_current");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(banners(s)).toEqual([]);
    s.undo();
  });

  it("the banner goes with the controller", async () => {
    const s = setup("update_available");
    await s.fc.flush();
    s.undo();
    expect(banners(s)).toEqual([]);
  });
});

describe("engine controller", () => {
  it("probes at bind and writes the facts to the store", async () => {
    const s = setup("idle");
    expect(s.phase()).toBe("checking");
    await s.fc.flush();
    expect(s.phase()).toBe("idle");
    expect(s.store.getState().engine.error).toBeNull();
    s.undo();
  });

  it("follows the engine on the poll cadence, from facts only", async () => {
    const s = setup("missing");
    await s.fc.flush();
    expect(s.phase()).toBe("not_installed");
    s.fake.set("stopped");
    await s.fc.advance(ENGINE_POLL_MS - 1);
    expect(s.phase()).toBe("not_installed");
    await s.fc.advance(1);
    expect(s.phase()).toBe("not_running");
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("idle");
    s.fake.set("incompatible");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("incompatible");
    s.fake.set("unreachable");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("not_running");
    expect(s.fake.probes()).toBe(5);
    s.undo();
  });

  it("a failed read clears the facts and says why; the next good read restores them", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.fake.set("error");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.store.getState().engine.probe).toBeNull();
    expect(s.store.getState().engine.error).toBe(MOCK_ENGINE_ERROR);
    expect(s.phase()).toBe("unreadable");
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.phase()).toBe("idle");
    expect(s.store.getState().engine.error).toBeNull();
    s.undo();
  });

  it("the switch defaults off: an idle engine is never told to route", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.policies).toEqual([]);
    expect(s.phase()).toBe("idle");
    s.undo();
  });

  it("turning the switch on sends it once with the next revision, and the engine routes", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.fake.policies).toEqual([policy(1, true)]);
    expect(s.phase()).toBe("routing");
    expect(s.checks.has(ENGINE_SWITCH)).toBe(true);
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies).toHaveLength(1);
    await s.settings.set(SWITCH, false);
    await s.fc.flush();
    expect(s.fake.policies[1]).toEqual(policy(3, false));
    expect(s.phase()).toBe("idle");
    expect(s.checks.has(ENGINE_SWITCH)).toBe(false);
    s.undo();
  });

  it("an engine that routes while the user's switch is off is told to stop, but only after the settings loaded", async () => {
    let release: (doc: unknown) => void = () => {};
    const slow: SettingsBackend = { kind: "memory", load: () => new Promise((r) => (release = r)), save: async () => {} };
    const s = setup("filtering", slow);
    await s.fc.flush();
    expect(s.fake.policies).toEqual([]);
    release({ schema: 4, values: {} });
    await s.fc.flush();
    expect(s.fake.policies).toEqual([policy(3, false)]);
    s.undo();
  });

  it("a stored on reaches an idle engine after load", async () => {
    const s = setup("idle", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([policy(1, true)]);
    s.undo();
  });

  it("sends_the_whole_policy", async () => {
    const values = {
      [ENGINE_SWITCH]: true,
      [GLOBAL_SWITCH]: false,
      "apps.levels": { firefox: "off", chrome: "sieve" },
      "filtering.blockedDomains": ["ads.example"],
      "filtering.allowedDomains": ["ok.ads.example"],
      "filtering.userRules": ["||rule.example^", "@@||ok.rule.example^"],
      "filtering.exclusions": ["bank.example"],
    };
    const s = setup("idle", memoryBackend({ schema: 4, values }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([
      {
        revision: 1,
        engine: true,
        sieving: false,
        off_apps: ["firefox"],
        https: false,
        lists: null,
        domain_lists: [
          { kind: "block", entries: ["ads.example"], enabled: true },
          { kind: "allow", entries: ["ok.ads.example"], enabled: true },
        ],
        user_rules: ["||rule.example^", "@@||ok.rule.example^"],
        exclusions: ["bank.example"],
      },
    ]);
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies, "the engine holds it now: nothing more to send").toHaveLength(1);
    s.undo();
  });

  it("an_off_app_change_alone_is_sent", async () => {
    const s = setup("filtering", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([]);
    await s.settings.set("apps.levels", { firefox: "off" });
    await s.fc.flush();
    expect(s.fake.policies).toEqual([{ ...policy(3, true), off_apps: ["firefox"] }]);
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies).toHaveLength(1);
    s.undo();
  });

  it("same_policy_in_another_order_sends_nothing", async () => {
    const values = { [ENGINE_SWITCH]: true, "apps.levels": { b: "off", a: "off" }, "filtering.blockedDomains": ["y.example", "x.example"] };
    const s = setup("filtering", memoryBackend({ schema: 4, values }));
    await s.fc.flush();
    expect(s.fake.policies).toHaveLength(1);
    await s.settings.set("apps.levels", { a: "off", b: "off" });
    await s.settings.set("filtering.blockedDomains", ["x.example", "y.example"]);
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies, "order means nothing to the engine").toHaveLength(1);
    s.undo();
  });

  it("an_untouched_list_selection_stays_the_catalogues_defaults", async () => {
    const s = setup("idle", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies[0].lists).toBeNull();
    s.undo();
  });

  it("a_changed_list_selection_is_sent_as_the_ids_of_the_lists_on", async () => {
    const { lists } = await createMockFilterLists().catalogue();
    const on = lists.find((l) => l.default === "on")!;
    const off = lists.find((l) => l.default === "off")!;
    const gated = lists.find((l) => l.default === "gated")!;
    const s = setup("idle", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true, "filters.lists": { [on.id]: "off", [off.id]: "on", [gated.id]: "on" } } }));
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS);
    const sent = s.fake.policies.at(-1)!.lists!;
    expect(sent).toContain(off.id);
    expect(sent).not.toContain(on.id);
    expect(sent, "a gated list stays off whatever is stored").not.toContain(gated.id);
    expect(sent).toEqual(lists.filter((l) => (l.default === "on" && l.id !== on.id) || l.id === off.id).map((l) => l.id));
    const count = s.fake.policies.length;
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.policies, "the engine holds it now").toHaveLength(count);
    await s.settings.set("filters.lists", {});
    await s.fc.flush();
    expect(s.fake.policies.at(-1)!.lists, "back to the defaults").toBeNull();
    s.undo();
  });

  it("a_catalogue_that_cannot_be_read_changes_no_list_and_is_read_again", async () => {
    const mock = createMockFilterLists();
    const { lists } = await mock.catalogue();
    const off = lists.find((l) => l.default === "off")!;
    let down = true;
    const source: FilterListSource = { ...mock, catalogue: () => (down ? Promise.reject(new Error("no")) : mock.catalogue()) };
    const s = setup("idle", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true, "filters.lists": { [off.id]: "on" } } }), source);
    await s.fc.flush();
    expect(s.fake.policies.at(-1)!.lists, "the engine's own selection, unchanged").toBeNull();
    expect(s.fake.policies.at(-1)!.engine, "and the rest of the policy still goes").toBe(true);
    down = false;
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.policies.at(-1)!.lists).toContain(off.id);
    s.undo();
  });

  it("the_default_resolvers_are_the_engines_so_nothing_is_sent", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.upstreams).toEqual([]);
    expect(s.store.getState().engine.dnsError ?? null).toBeNull();
    s.undo();
  });

  it("the_resolver_setting_reaches_the_engine_in_its_order_and_only_once", async () => {
    const s = setup("idle");
    await s.fc.flush();
    const list = ["tls://b.example", "https://a.example/dns-query"];
    await s.settings.set("filtering.upstreams", list);
    await s.fc.flush();
    expect(s.fake.upstreams).toEqual([{ revision: 1, upstreams: list }]);
    await s.fc.advance(ENGINE_POLL_MS * 2);
    expect(s.fake.upstreams, "the engine holds it").toHaveLength(1);
    await s.settings.set("filtering.upstreams", [...list].reverse());
    await s.fc.flush();
    expect(s.fake.upstreams.at(-1), "the order is the order they are tried in").toEqual({ revision: 2, upstreams: [...list].reverse() });
    s.undo();
  });

  it("a_refused_resolver_list_is_said_and_tried_again_at_the_next_probe", async () => {
    const s = setup("idle", memoryBackend({ schema: 5, values: { "filtering.upstreams": ["tls://a.example"] } }));
    const accepting = s.fake.source.setDnsUpstreams;
    let refused = 0;
    s.fake.source.setDnsUpstreams = async () => {
      refused++;
      throw new Error("udp://1.1.1.1 is not an encrypted upstream");
    };
    await s.fc.flush();
    expect(s.store.getState().engine.dnsError).toContain("is not an encrypted upstream");
    const first = refused;
    await s.fc.flush();
    expect(refused, "never in a loop").toBe(first);
    s.fake.source.setDnsUpstreams = accepting;
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.store.getState().engine.dnsError).toBeNull();
    s.undo();
  });

  it("an_empty_resolver_setting_sends_nothing_and_an_unreachable_engine_is_not_asked", async () => {
    const s = setup("idle", memoryBackend({ schema: 5, values: { "filtering.upstreams": [] } }));
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.upstreams).toEqual([]);
    s.undo();
    const absent = setup("missing", memoryBackend({ schema: 5, values: { "filtering.upstreams": ["tls://a.example"] } }));
    await absent.fc.advance(ENGINE_POLL_MS);
    expect(absent.fake.upstreams).toEqual([]);
    expect(absent.store.getState().engine.dnsError ?? null).toBeNull();
    absent.undo();
  });

  it("a refused policy is said and retried at the next probe, never in a loop", async () => {
    const s = setup("idle", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    const accepting = s.fake.source.setPolicy;
    let refused = 0;
    s.fake.source.setPolicy = async () => {
      refused++;
      throw new Error("a policy of 900000 bytes is over the 524288 byte limit");
    };
    await s.fc.flush();
    await s.fc.flush();
    expect(refused).toBe(1);
    expect(s.store.getState().engine.actionError).toMatch(/over the/);
    await s.fc.advance(ENGINE_POLL_MS);
    expect(refused).toBe(2);
    s.fake.source.setPolicy = accepting;
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.store.getState().engine.actionError).toBeNull();
    s.undo();
  });

  describe("law: an oversized policy never holds back an off switch", () => {
    /** Rules well over the engine's limit, as an older build could have stored them. */
    const OVERSIZED = Array.from({ length: 20_000 }, (_, i) => `||a-rule-for-host-number-${i}.tracker.example^$third-party`);
    const stored = (values: object = {}) => memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true, "filtering.userRules": OVERSIZED, ...values } });

    /** The engine's own refusal (`policy::accept`), so a test cannot pass by an unsized fake. */
    function capped(s: ReturnType<typeof setup>) {
      const accepting = s.fake.source.setPolicy;
      const refused: number[] = [];
      s.fake.source.setPolicy = async (p) => {
        const size = new TextEncoder().encode(JSON.stringify(p)).length;
        if (size > MAX_POLICY_BYTES) {
          refused.push(size);
          throw new Error(`a policy of ${size} bytes is over the ${MAX_POLICY_BYTES} byte limit`);
        }
        return accepting(p);
      };
      return refused;
    }

    const held = (s: ReturnType<typeof setup>) => s.store.getState().engine.probe;
    const inForce = (s: ReturnType<typeof setup>) => {
      const pipe = held(s)?.pipe;
      return pipe?.kind === "welcome" ? pipe.status.policy : null;
    };

    it("the rules really are over the limit", () => {
      expect(new TextEncoder().encode(JSON.stringify(OVERSIZED)).length).toBeGreaterThan(MAX_POLICY_BYTES);
    });

    it("engine false reaches the engine while the rules are over the limit, and it stops routing", async () => {
      const s = setup("filtering", stored());
      const refused = capped(s);
      await s.fc.flush();
      await s.settings.set(SWITCH, false);
      await s.fc.flush();
      expect(refused, "nothing the engine must refuse is sent").toEqual([]);
      expect(s.fake.policies.at(-1)).toMatchObject({ engine: false, user_rules: [] });
      expect(inForce(s)?.engine).toBe(false);
      expect(s.phase()).toBe("idle");
      s.undo();
    });

    it("the Sieving switch and one app's Off arrive too, the first send included", async () => {
      const s = setup("filtering", stored({ [GLOBAL_SWITCH]: false }));
      capped(s);
      await s.fc.flush();
      expect(inForce(s)?.sieving, "a stored off, at the first send").toBe(false);
      await s.settings.set("apps.levels", { firefox: "off" });
      await s.fc.flush();
      expect(inForce(s)?.off_apps).toEqual(["firefox"]);
      s.undo();
    });

    it("the rules the engine holds stay as they are, and the user is told why theirs did not arrive", async () => {
      const s = setup("filtering", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true, "filtering.userRules": ["||kept.example^"] } }));
      capped(s);
      await s.fc.flush();
      expect(inForce(s)?.user_rules).toEqual(["||kept.example^"]);
      // Not a save, which would refuse it: an older build's stored value.
      await s.settings.replace({ schema: 5, values: { [ENGINE_SWITCH]: false, "filtering.userRules": OVERSIZED } });
      await s.fc.flush();
      expect(inForce(s)).toMatchObject({ engine: false, user_rules: ["||kept.example^"] });
      expect(s.store.getState().engine.actionError).toMatch(/your rules.*over the.*Your switches reached it/);
      s.undo();
    });

    it("sends nothing more once the switches are in force, and the error ends when the rules are back in range", async () => {
      const s = setup("filtering", stored());
      capped(s);
      await s.fc.flush();
      const sent = s.fake.policies.length;
      await s.fc.advance(ENGINE_POLL_MS * 3);
      expect(s.fake.policies, "the part the engine can take is already held").toHaveLength(sent);
      expect(s.store.getState().engine.actionError).toMatch(/your rules/);
      await s.settings.set("filtering.userRules", ["||small.example^"]);
      await s.fc.flush();
      expect(inForce(s)?.user_rules).toEqual(["||small.example^"]);
      expect(s.store.getState().engine.actionError).toBeNull();
      s.undo();
    });

    it("a refusal for any other reason also lets the switches through, once", async () => {
      const s = setup("filtering", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: true } }));
      await s.fc.flush();
      const accepting = s.fake.source.setPolicy;
      const asked: EnginePolicy[] = [];
      s.fake.source.setPolicy = async (p) => {
        asked.push(p);
        if (p.user_rules.length > 0) throw new Error("the engine will not take these");
        return accepting(p);
      };
      await s.settings.replace({ schema: 5, values: { [ENGINE_SWITCH]: false, "filtering.userRules": ["||a.example^"] } });
      await s.fc.flush();
      expect(inForce(s)).toMatchObject({ engine: false, user_rules: [] });
      expect(asked.filter((p) => p.user_rules.length > 0), "tried, and tried once more after the switches went: never in a loop").toHaveLength(2);
      await s.fc.advance(ENGINE_POLL_MS);
      expect(asked.filter((p) => p.user_rules.length > 0), "then at each probe").toHaveLength(3);
      expect(s.store.getState().engine.actionError).toMatch(/your rules.*will not take/);
      s.undo();
    });

    it("off-apps over the limit, as an old file could hold, cannot hold back the engine switch", async () => {
      const apps = Object.fromEntries(Array.from({ length: 30_000 }, (_, i) => [`an-app-named-number-${i}`, "off"]));
      const s = setup("filtering", memoryBackend({ schema: 5, values: { [ENGINE_SWITCH]: false, "apps.levels": apps } }));
      capped(s);
      await s.fc.flush();
      expect(inForce(s)).toMatchObject({ engine: false, off_apps: [] });
      expect(s.phase()).toBe("idle");
      s.undo();
    });
  });

  it("refused (this copy is not the installed one): a flip sends nothing, and nothing claims routing", async () => {
    const s = setup("refused");
    await s.fc.flush();
    expect(s.phase()).toBe("refused");
    expect(engineLockReason(s.store.getState().engine)).not.toBeNull();
    // The Settings row is locked; even a write that got past it (another window, an old file) is not sent.
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.policies).toEqual([]);
    expect(s.checks.has(ENGINE_SWITCH)).toBe(false);
    expect(s.store.getState().engine.actionError ?? null).toBeNull();
    s.undo();
  });

  it("law: no policy is sent in any phase that cannot take one, a stored on included; it waits untouched until the engine can", async () => {
    for (const scenario of ["missing", "stopped", "starting", "unreachable", "refused", "incompatible", "error"] as const) {
      const s = setup(scenario, memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
      await s.fc.flush();
      await s.fc.advance(ENGINE_POLL_MS * 2);
      expect(s.fake.policies, scenario).toEqual([]);
      expect(s.settings.get(SWITCH), scenario).toBe(true);
      s.undo();
    }
    const s = setup("refused", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.fake.policies).toEqual([]);
    // The installed copy's turn: the engine answers, and the stored value goes once.
    s.fake.set("idle");
    await s.fc.advance(ENGINE_POLL_MS);
    expect(s.fake.policies).toEqual([policy(1, true)]);
    expect(s.phase()).toBe("routing");
    s.undo();
  });

  it("a retained Status cannot send a saved change after a failed read", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.store.setEngine({ ...s.store.getState().engine, error: "read failed" });
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.phase()).toBe("unreadable");
    expect(s.fake.policies).toEqual([]);
    expect(s.settings.get(SWITCH)).toBe(true);
    s.undo();
  });

  it("a crash loop shows one Home banner, gone when the user turns routing off and on", async () => {
    const s = setup("crash_loop", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    const banners = () => s.notices.list().filter((n) => n.surface === "banner").map((n) => n.text);
    await s.fc.flush();
    expect(s.phase()).toBe("crash_loop");
    expect(banners()).toEqual([CRASH_LOOP_BANNER]);
    await s.fc.advance(ENGINE_POLL_MS);
    expect(banners()).toHaveLength(1);
    await s.settings.set(SWITCH, false);
    await s.fc.flush();
    await s.settings.set(SWITCH, true);
    await s.fc.flush();
    expect(s.phase()).toBe("routing");
    expect(banners()).toEqual([]);
    s.undo();
  });

  it("pausing AdGuard runs only on request, then probes: the waiting engine routes with the service left stopping", async () => {
    const s = setup("adguard", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.phase()).toBe("adguard");
    const probes = s.fake.probes();
    await s.controller.stopAdguard();
    expect(s.fake.probes()).toBe(probes + 1);
    expect(s.phase()).toBe("routing");
    expect(s.store.getState().engine.probe?.adguard).toBe("stopping");
    expect(s.store.getState().engine.adguard).toBeNull();
    await s.controller.startAdguard();
    expect(s.store.getState().engine.actionError).toMatch(/AdGuard/);
    expect(s.phase()).toBe("routing");
    s.undo();
  });

  it("starting AdGuard's stopped service makes the routing engine wait", async () => {
    const s = setup("filtering", memoryBackend({ schema: 4, values: { [ENGINE_SWITCH]: true } }));
    await s.fc.flush();
    expect(s.phase()).toBe("routing");
    await s.controller.startAdguard();
    expect(s.phase()).toBe("adguard");
    s.undo();
  });

  it("a refused AdGuard action is said, and the facts stay the engine's", async () => {
    const s = setup("idle");
    await s.fc.flush();
    await s.controller.stopAdguard();
    expect(s.store.getState().engine.actionError).toBe(`AdGuard was not paused: ${MOCK_ADGUARD_ERROR}`);
    expect(s.phase()).toBe("idle");
    s.undo();
  });

  it("never overlaps probes: the next is scheduled after the previous settled", async () => {
    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    let calls = 0;
    const mock = createMockEngine("idle");
    const slow: EngineSource = {
      ...mock,
      probe: () => {
        calls++;
        return new Promise((r) => (resolve = r));
      },
    };
    const deps = { settings: createSettingsStore(memoryBackend()), checks: createPassedChecks(), notices: createNoticeBus(), filterLists: createMockFilterLists() };
    const undo = createEngineController({ engine: slow, store, clock: fc.clock, ...deps }).bind();
    await fc.advance(ENGINE_POLL_MS * 5);
    expect(calls).toBe(1);
    expect(fc.pending()).toBe(0);
    resolve!(await mock.probe());
    await fc.flush();
    expect(enginePhase(store.getState().engine)).toBe("idle");
    expect(fc.pending()).toBe(1);
    undo();
  });

  it("stops polling on undo, and a probe in flight then writes nothing", async () => {
    const s = setup("idle");
    await s.fc.flush();
    s.undo();
    expect(s.fc.pending()).toBe(0);
    const before = s.fake.probes();
    await s.fc.advance(ENGINE_POLL_MS * 3);
    expect(s.fake.probes()).toBe(before);

    const fc = fakeClock();
    const store = createStore();
    let resolve: ((p: EngineProbe) => void) | null = null;
    const mock = createMockEngine("idle");
    const deps = { settings: createSettingsStore(memoryBackend()), checks: createPassedChecks(), notices: createNoticeBus(), filterLists: createMockFilterLists() };
    const undo = createEngineController({ engine: { ...mock, probe: () => new Promise((r) => (resolve = r)) }, store, clock: fc.clock, ...deps }).bind();
    undo();
    resolve!(await mock.probe());
    await fc.flush();
    expect(store.getState().engine.probe).toBeNull();
    expect(fc.pending()).toBe(0);
  });
  describe("the certificate", () => {
    it("is read after each probe while the engine takes a policy, and cleared when it cannot", async () => {
      const s = setup("idle");
      await s.fc.flush();
      expect(s.fake.certReads()).toBe(1);
      expect(s.store.getState().engine.cert?.state).toBe("not_installed");
      s.fake.set("stopped");
      await s.fc.advance(ENGINE_POLL_MS);
      expect(s.fake.certReads()).toBe(1);
      expect(s.store.getState().engine.cert).toBeNull();
      s.fake.set("idle");
      await s.fc.advance(ENGINE_POLL_MS);
      expect(s.fake.certReads()).toBe(2);
      s.undo();
    });

    it("a failed read sets certError and clears the cert; the next good read restores it", async () => {
      const s = setup("idle");
      await s.fc.flush();
      s.fake.setCert("error");
      await s.fc.advance(ENGINE_POLL_MS);
      expect(s.store.getState().engine.cert).toBeNull();
      expect(s.store.getState().engine.certError).toBe(MOCK_CERT_ERROR);
      expect(s.phase()).toBe("idle");
      s.fake.setCert("installed");
      await s.fc.advance(ENGINE_POLL_MS);
      expect(s.store.getState().engine.cert?.state).toBe("installed");
      expect(s.store.getState().engine.certError).toBeNull();
      s.undo();
    });

    it("the unavailable switch reads off, so the policy sends https false whatever is stored", async () => {
      const s = setup("idle", memoryBackend({ schema: 4, values: { [SWITCH]: true, [HTTPS_SWITCH]: true } }));
      await s.fc.flush();
      expect(s.fake.policies).toEqual([policy(1, true)]);
      s.undo();
    });

    it("an engine holding https on while the switch is off is told off: both switches go in one policy", async () => {
      const s = setup("idle");
      await s.fc.flush();
      await s.fake.source.setPolicy({ ...policy(1, false), https: true });
      s.fake.policies.length = 0;
      await s.fc.advance(ENGINE_POLL_MS);
      expect(s.fake.policies.at(-1)).toMatchObject({ engine: false, https: false });
      s.undo();
    });

    it("Reinstall is passed on; a refusal is said in its own field and the facts stay the engine's", async () => {
      const s = setup("idle");
      await s.fc.flush();
      await s.controller.installRoot();
      expect(s.store.getState().engine.certActionError).toBe(`The certificate was not reinstalled: ${MOCK_HTTPS_OFF}`);
      expect(s.store.getState().engine.actionError).toBeNull();
      s.undo();
    });
  });
});
