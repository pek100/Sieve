# UI backlog: filter lists, rules and allowlist, settings password, first-run guide, desktop notifications

Stream `ui-backlog`, branch `wf-ui-backlog`, base `main` at f0fe2cb. Spec: the open UI rows of `docs/plans/2026-10-17-parity.md` plus the five items below. Everything is app side (`src/**`, `src-tauri/**`). No file under `engine/` changes.

Not this stream (do not touch): the DNS card and proxy removal, the Log route, the certificate UI, the Apps VM group.

## 1. Goal

A person can, in the app:

1. See the filter-list catalogue, turn lists on and off, and see each list's applied and skipped counts (or that there are none yet).
2. Use tracking and annoyance options that are nothing but groups of those lists.
3. Write user rules with friendly per-line errors, keep a domain allowlist, and block a domain by name.
4. Set a settings password (hashed with Argon2id, never stored plain), lock and unlock, with every settings write behind it.
5. Be walked through a first-run guide that explains Sieve and offers to pause AdGuard through the existing engine controller, and that changes nothing on the network.
6. Turn on desktop notifications for the problems the app already raises.

The engine does not consume any of this yet (slice 4 onward). All copy says so while it is true. Sieve still blocks nothing and no screen may imply otherwise.

## 2. Parity row audit (the plan's "Now" column is stale; checked against the code on f0fe2cb)

| Row | Capability | State in code | This stream |
|---|---|---|---|
| 12 | Other filters count row | none | Yes: per-group "2 of 5 on", derived |
| 13, 15 | User rules list, raw editor | none | Yes: one text editor inline on `/filters`, not a second window |
| 14 | Rule form builder | none | Partly: "Block a site" field writes `\|\|host^`; no comment or subdomain fields (a rule line can carry them) |
| 16, 17 | Catalogue, add from catalogue | none (engine has `catalogue::LISTS`) | Yes: a catalogue switch is both |
| 22 | Allowlist | none | Yes |
| 24, 25, 32 | Annoyances, tracking level, reset custom | none | Yes as list groups (decision D3). The G3 sub-keys 26 to 28 and 30 are not built: no engine behaviour behind them |
| 35 | Settings password | none | Yes |
| 47, 48 | First run | none | Yes |
| 75 | Desktop notifications | none | Yes |
| 4, 6, 68 to 70, 76 | Banner, modules, settings, toasts | built | No change |
| 3 | Quick module chips | none | No: the flat UI rule rejects redundant chips |
| 11, 18 to 21, 23, 33, 36, 41, 42 | Language lists, custom lists, per-filter actions, DNS and parental lists | none | No: each needs engine download or list operations that do not exist. Slice 4 and later |
| 54 | Drill-down by host | none | Not in the spec's item list; see open question Q5 |
| 72, 73 | Support, About | none | Not in the spec's item list; see Q5 (a public support URL is needed; About overlaps `wf-updates`) |
| 56 to 58 | Log | none | Other stream |

## 3. Design decisions

**D1. The catalogue's one owner is the engine crate; the app reads it, never copies it (S29, S49).** `src-tauri` gets a path dependency on `sieve-filter` (as it already has on `sieve-ipc`) and a command `filter_catalogue` that serialises `sieve_filter::catalogue::LISTS`, with `report: null` for every list. Reason: a TS copy of the table rots, and without the Rust read the desktop build would have no lists to show. Plan 1.2 already says the app may use `sieve-filter` to validate rules. Cost: adblock-rust compiles into the app. Accepted; the alternative is two parsers.

**D2. Absent is not zero (S17).** A list's `report` is `{applied, skipped, reasons}` or `null`. Null reads "Not loaded yet", never 0. The mock serves both through `?lists=pending|loaded|empty|error` (default `pending`, the truth today), with the shapes taken from a fixture, `src/data/fixtures/filter-lists-v1.json`, which a Rust test and a TS law both read.

**D3. Tracking and annoyance options are list groups, not settings (minimal basis, S52).** `listGroup(list)` derives `tracking`, `annoyances` or `general` from the catalogue's title (`/annoyance/i`, `/tracking/i`). A group's switch writes all its selectable lists; its state is derived (all on, all off, "2 of 5 on") and never stored. Reason: the plan's level-plus-custom scheme has nothing behind it until slice 9, and a stored level would disagree with the selection. A law checks that the derivation puts every catalogue list in a group, and that the tracking and annoyance groups are not empty, so a renamed list fails a test instead of silently moving.

**D4. Selections and rules are registry settings (B5), new section `filters`.** `filters.lists` (map of list id to `on` or `off`, only differences from the catalogue's default are stored; unknown ids kept), `filters.userRules` (list, element shape `rule`), `filters.allowlist` (list, element shape `domain`). So export, import with preview, reset and search work with no new code, and the existing `SettingRow` gives "Open Filters" from the section id. Adding keys does not bump `SETTINGS_SCHEMA`. New element specs `rule` and `domain` mean an import cannot smuggle a `trusted-*` scriptlet or a junk host in: the registry refuses it (S30). B6 from the parity plan is this: the registry's `list` kind plus one `DomainList` component, which slice 7's "Not decrypted" view can reuse.

**D5. Gated lists stay off structurally.** `Default::Gated` lists show with a disabled switch and "Waiting on testing". `listOn` returns false for them whatever is stored, and `setListOn` refuses them, so the uBO gate of slice 10 cannot be bypassed from the UI or an import.

**D6. Rule validation has two layers with a cross-witness (S3, S14), not two mirrored parsers.** `src/core/rules.ts` is pure and owns the friendly words: blank and comment lines pass, a bare host gets a hint ("Did you mean ||example.com^?"), a `trusted-` scriptlet is refused with the reason, whitespace inside a network rule, an empty `||`, an unclosed `##+js(` and over-long input are errors. It knows no list of `$` options; those would rot. The authority is `sieve-filter`'s parser, through `rule_check(lines)` in Rust: `RuleEngine::compile` with `trusted: false`, the whole text first and per line only when `reports()` says something was skipped (no engine change is needed; the crate's `report` is private). `friendlyRuleReason(reason)` turns the parser's words into a sentence, with the raw reason kept beside it. The browser mock runs only the TS layer. `src/data/fixtures/user-rules-v1.json` holds cases with the expected answer of each layer; a TS test and a Rust test read the same file. Save is refused while any line has an error.

**D7. An allowlist entry is a host; the rule is derived.** `normalizeDomain(raw)` accepts a pasted URL, lower-cases, and gives one friendly error per failure (spaces, one label, IP address, too long, bad characters). It uses the same rule as Rust `dns::rules::host_name`, and the fixture has cases for both. `allowRule(host)` gives `@@||host^$important`, `blockRule(host)` gives `||host^`. `filterPolicy(doc, catalogue)` is the one function that builds what slice 4 will send in `SetPolicy` (lists on, user rules, allow rules). It has no live caller until then: it is here so that the semantics are tested in one place. Delete it instead if the orchestrator's merge finds `wf-domain-policy` already defines this payload.

**D8. Password verification lives in Rust and the hash never reaches the webview (S30).** `src-tauri/src/lock.rs` owns `<app data>/settings-lock.json`: `{v: 1, phc: "$argon2id$..."}`, written atomically (temp file then rename). Argon2id via the `argon2` crate, m=19456 KiB, t=2, p=1 (OWASP's minimum profile); the PHC string carries salt and parameters, so they can change later. Salt from the OS RNG. Commands run in `spawn_blocking`: `lock_status`, `lock_set {current, next}`, `lock_verify {password}`, `lock_clear {current}`. After `MAX_TRIES` (5) wrong answers, `RETRY_AFTER_SECS` (30) through a `Throttle` that takes the time as an argument. Not a settings key: export, import and reset can then neither carry nor clear it (a test proves it).

**D9. The lock is a gate in the UI, and the copy says so.** It stops a person using the open app. It does not stop code or a person who can edit files in the same Windows account, and Rust commands such as `engine_set_policy` are not gated. An unreadable lock file reads `unreadable`: settings stay locked and the block says why. It affects settings only and never the network. See Q1.

**D10. One write gate.** `createLockController` (`src/data/lock-controller.ts`) owns the state: `checking | none | locked | unlocked | unreadable`. It keeps its own observable, like `passedChecks`, so `store.ts` stays out of it. `controller.guard(fn)` runs `fn` when writes are allowed. Otherwise it parks `fn`, asks for unlock, and runs it on success or drops it on cancel. Applied in exactly three places: the setter of `useSetting`, the writers in `useSettingsView`, and `useEngineActions`. So the master switch, theme, apps toggles, pins, rows, import and the AdGuard offer are all covered with no change to those components. Internal safety writes (`dns-controller` turning a failed switch off) stay direct: they only ever turn things off. `useSettingsView.lockOf` returns a new `{kind: "password"}` first, so a locked row shows disabled with a note and an Unlock button.

**D11. Reading stays open except the log.** Settings and Filters stay visible and read only while locked. `<LockGate>` replaces its children with the unlock prompt, for the log route, which shows browsing history. This stream only exports it; the Log route belongs to `wf-app-log`. Merge note for the orchestrator: wrap the log screen in `<LockGate>` when both have landed.

**D12. Relock on idle, one dial.** `password.idleMinutes` (5 to 60, step 5, default 15) gives the `password` section its required setting and is a real choice. The clock is injected, activity comes from `pointerdown` and `keydown` on the window (bound in `bindLock`), and "Lock now" is a top-bar `IconButton` shown only while a password exists. A tray app stays open for days, so "until restart" would mean always unlocked.

**D13. First-run guide is a takeover of the content area, gated by data.** `<WelcomeGate>` in `AppShell` renders `<WelcomeScreen>` in place of the routed screen while `runtime.welcomeOnFirstRun && !settings.get("startup.welcomeDone")`, and only after `settings.ready` so that a returning user never sees a flash. `welcomeOnFirstRun` is `isTauri || ?welcome=1`. So the existing e2e specs and component tests, which open without it, stay untouched, and the same predicate is tested for both. `startup.welcomeDone` is a normal row ("Welcome guide finished", off shows it again).

**D14. The guide never changes the network, by construction.** Steps come from pure `welcomeSteps(engineSlice)`: (1) what Sieve shows and that it blocks nothing yet; (2) what can change traffic, derived from the registry's available data switches, each read only and off; (3) AdGuard, only while `probe.adguard === "running"` and the engine is installed, with `ADGUARD_PAUSE_TEXT` and `useEngineActions().stopAdguard` (a new `welcomeAdguard` predicate: the existing `adguardOffer` answers only when the engine is already waiting, which needs the switch on). No step writes a data switch. Skip is always one click. Plan 1.5's "Filter all traffic" button is not included (Q4).

**D15. Notifications: seam plus the official plugin.** `Desktop` gains `notifications: {granted(), request(), send(title, body)}`, null outside Tauri as today. `bindNotifications(rt, isFocused)` reads the notice bus: `desktopWorthy(notice)` is `kind === "error" && surface === "banner"`, derived, with no per-call flag, which today covers the crash loop and stranded-DNS banners. Sends once per notice id, only while `notifications.desktop` is on and the window lacks focus. Turning on asks permission; refused turns it back off with a toast (same pattern as launch at startup). Setting default off, `desktopOnly`. Note on the spec: `tauri-plugin-notification` is not in `Cargo.lock` or `package.json`, and the stream text says "if already available, else behind a seam". The seam is built, and the plugin is also added (`tauri-plugin-notification`, `@tauri-apps/plugin-notification`, permission `notification:default`), because parity row 75 names it and a seam with nothing behind it would be a toggle that does nothing. If the orchestrator wants no new dependency, drop only `tauriDesktop().notifications` (null) and make the row `unavailableUntil`: nothing else moves.

**D16. Navigation.** `/filters` is one appended `ROUTES` entry (label "Filters", the free `list` icon goes to `wf-app-log`, add a `filter` icon key). The real window's minimum is 960 wide, so 375 is the browser mock only. The nav gets `max-[480px]:px-2` and the lock button is hidden under 640, so 375 still fits after the Log route adds a fifth item (arithmetic: 5 x 32 + 16 + 8 = 184 nav, 24 mark, about 36 switch, 36 theme, gaps 12, page pads 32, scrollbar 8 = 332).

**D17. Flat UI.** No new `Card` variants or containers. Blocks use the flat `Card` (title, error boundary, loading, empty, error states). The screen uses `LayoutGrid`: lists span 6, rules and allowlist span 6, one column under 960. Dialogs float (allowed). The guide uses `EmptyState`'s one serif line. Skipped-rule reasons use `FloatingTooltip`. No dividers. Rows 44 px, hosts and rules in `font-mono`.

**D18. Resilience (frontend-resilience).** `parseFilterCatalogue` is the one normaliser: wrong `v` throws to the Card's error state, a malformed row is dropped and counted in a line, a bad `report` reads null. `parseLockStatus` maps anything unknown to `unreadable`. A selection with unknown ids, rules that no longer validate and an old settings document all render. Tests cover null, partial and old-schema shapes.

## 4. Exact files

New:
- `src/core/filter-lists.ts` (`listGroup`, `listOn`, `setListOn`, `setGroupOn`, `groupState`, `countText`, `filterPolicy`) and test
- `src/core/rules.ts` (`checkRuleLine`, `checkRuleText`, `friendlyRuleReason`, `normalizeDomain`, `allowRule`, `blockRule`) and test
- `src/core/lock.ts` (phases, `canWrite`, `passwordProblem`, `MIN_PASSWORD_CHARS`, copy) and test
- `src/core/welcome.ts` (`welcomeSteps`, `welcomeAdguard`, `dataSwitchSummary`) and test
- `src/data/filter-lists-source.ts`, `filter-lists-mock.ts` and test; `src/data/fixtures/filter-lists-v1.json`, `user-rules-v1.json`
- `src/data/lock-source.ts` (Tauri commands), `lock-mock.ts` (memory only, `?lock=none|set`, never persisted, test password from the mock), `lock-controller.ts` and test
- `src/hooks/use-filters.ts`, `use-lock.ts`, `use-welcome.ts`
- `src/app/filters/page.tsx` (thin)
- `src/components/sieve/filters/{filters-screen,list-catalogue,list-group,rules-editor,domain-list}.tsx`, `filters.test.tsx`
- `src/components/sieve/lock/{unlock-dialog,password-dialog,password-block,lock-gate,lock-button}.tsx`, `lock.test.tsx`
- `src/components/sieve/welcome/{welcome-gate,welcome-screen}.tsx`, `welcome.test.tsx`
- `src-tauri/src/filters.rs`, `src-tauri/src/lock.rs`
- `tests/laws/filters.test.ts` (law 13; renumber at merge if another stream took it), `tests/laws/lock.test.ts` (law 14)
- `tests/e2e/filters.spec.ts`, `lock.spec.ts`, `welcome.spec.ts`

Edited, append-only where shared:
- `src/core/settings/registry.ts`: element specs `rule` and `domain`; `noun` on `MapSetting`; sections `notifications`, `filters` (label "Filter lists"), `password`; keys `startup.welcomeDone`, `notifications.desktop`, `filters.lists`, `filters.userRules`, `filters.allowlist`, `password.idleMinutes`
- `src/core/settings/transfer.ts`: `formatValue` map case uses `noun` (it says "apps" today)
- `src/core/routes.ts`: one entry and the icon key
- `src/core/notices.ts`: `desktopWorthy`
- `src/data/protocol.ts`: wire types and parsers appended
- `src/data/source.ts`: `lists`, `lock`, `welcome` options; `createFilterListSource`, `createLockSource`
- `src/data/desktop.ts`: `notifications`; fakes in `src/hooks/runtime.test.ts`, `src/hooks/sieve-provider.test.tsx`
- `src/hooks/runtime.ts`: `filterLists`, `lock`, `lockController`, `welcomeOnFirstRun`, `bindLock`, `bindNotifications`
- `src/hooks/sieve-provider.tsx`: two binds
- `src/hooks/use-sieve.ts`: `useSetting` and `useEngineActions` through `guard`
- `src/components/sieve/settings/use-settings-view.ts`, `setting-row.tsx`, `settings-screen.tsx` (password lock, Password block)
- `src/components/sieve/shell/app-shell.tsx`, `top-bar.tsx`; `primitives/segmented.tsx` (one class)
- `src-tauri/Cargo.toml`, `Cargo.lock`, `src-tauri/src/lib.rs`, `src-tauri/capabilities/default.json`; `package.json`, `pnpm-lock.yaml`
- `tests/e2e/settings.spec.ts` (row count 13, rail labels), `alignment.spec.ts`, `scroll.spec.ts`, `screens.spec.ts` (add `/filters`)
- `docs/conventions.md` (seams table, section 6, section 7 laws, section 8 capabilities), `docs/plans/2026-10-17-parity.md` (Now column for the rows in section 2 only)

## 5. Offline acceptance criteria

Environment: PowerShell. `$env:CARGO_BUILD_JOBS='8'` before every cargo command. First `pnpm install --frozen-lockfile --offline`, falling back to `--frozen-lockfile`. No test reaches the internet. No test elevates, stops a service or touches the real `E:\Sieve` install.

Whole suites, all green:
- `pnpm typecheck`, `pnpm lint`, `pnpm test`
- `pnpm rust:test`, `pnpm rust:lint`
- e2e through the lease, after reading `nvidia-smi` (wait if another project holds over half the card), launched through `cmd /c` as `docs/conventions.md` section 7 requires: `powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-e2e-ui-backlog -NeedMiB 300 -- cmd /c pnpm e2e`. Both projects, 1280x800 and 375x812.

Filter lists:
- [ ] Law 13: fixture ids, titles, URLs, licences and defaults equal `engine/crates/sieve-filter/src/catalogue.rs`, row by row and in order. Every list has a group; tracking and annoyances are not empty. No file under `src/components` names a list id or list title.
- [ ] Rust `filters::tests`: `filter_catalogue` serialises `LISTS` to the fixture's `pending` example exactly; every report is null.
- [ ] `filter-lists.test.ts`: only differences from the default are stored; a stored `on` for a gated list reads off and `setListOn` refuses it; `setGroupOn` skips gated lists; `groupState` gives all, none and "2 of 5"; unknown ids survive a write.
- [ ] `filters.test.tsx`: `pending` says "Not loaded yet" and never shows a 0; `loaded` shows the fixture's counts and the reasons in a tooltip; `error` shows the Card's error state; malformed rows, null, partial and old-schema catalogues render without throwing; the "not applied yet" line shows while every report is null and goes when one is not.
- [ ] e2e: toggling a list persists across reload; the group switch changes its lists; `?lists=loaded` shows counts; no horizontal scroll at 375; screenshots saved.

Rules and allowlist:
- [ ] `user-rules-v1.json` is read by `rules.test.ts` and Rust `filters::tests`, and each layer gives the recorded answer. At least: comment, bare host (hint), `||example.com^`, `@@||example.com^`, `##.ad`, `example.com##.ad`, unknown `$option`, space inside a rule, `||`, `##+js(trusted-x)` (refused by both), `##+js(` unclosed. Record what the parser really answers; do not edit an expected value to pass without saying so.
- [ ] `normalizeDomain` table test: `https://WWW.Example.com/a?b` gives `www.example.com`; `localhost`, `1.2.3.4`, `a b.com`, a 254-character name each give their own friendly error. Same table in a Rust test against `dns::rules::host_name`.
- [ ] Registry law addition: `isValidValue("filters.userRules", ["##+js(trusted-x)"])` is false; `planImport` refuses it with the reason and keeps the current value.
- [ ] Component tests: an error names its line number and Save is disabled; fixing it enables Save; adding a duplicate domain is absorbed; removal gives an undo toast and undo restores; "Block a site" appends `||host^` to the editor.
- [ ] `allowRule`, `blockRule`, `filterPolicy` unit tests.

Password:
- [ ] Rust `lock::tests` with a temp dir: `lock_set` writes a file whose text starts its hash with `$argon2id$` and does not contain the password; two sets of one password give two salts; verify right and wrong; a wrong `current` refuses `lock_set` and `lock_clear`; a short password is refused in Rust too; corrupt file reads `unreadable` and is never overwritten by `lock_set`; a failed write leaves the old file; `Throttle` refuses after 5 and allows again after 30 s (time passed in, no sleeping).
- [ ] Law 14: `MIN_PASSWORD_CHARS` agrees between TS and Rust. No file in `src` other than `lock-mock.ts` and tests names a stored password field. `lock_status` and `lock_verify` response types have no hash field. No `src/components` file calls `settings.set`, `settings.reset` or `settings.replace` except `use-settings-view.ts`, which must also contain `guard(`.
- [ ] `lock-controller.test.ts` with a fake clock: every phase; a parked write runs after unlock and is dropped on cancel; activity pushes back the idle relock; relock happens at `password.idleMinutes`; `checking` parks instead of dropping.
- [ ] `lock.test.tsx`, while locked, one test per writer: master switch, theme, app toggle, pin, setting row, import, reset all, AdGuard pause. Each asks for unlock and writes nothing; after unlock the write lands. `<LockGate>` hides its children while locked. `exportText` output contains nothing of the lock; `resetPlan` leaves it set.
- [ ] e2e with `?lock=none`: set, lock, wrong password shows a message, unlock. With `?lock=set`: Settings rows are disabled with the note. No horizontal scroll at 375.

First run:
- [ ] `welcome.test.ts`: the AdGuard step appears only with AdGuard running and the engine installed; the data-switch step lists exactly the registry's available data switches.
- [ ] `welcome.test.tsx`: `isTauri: true` with a fresh doc shows the guide; a stored done flag never renders it, not even for one frame before `ready`; `isTauri: false` without `?welcome=1` never shows it; Skip and Finish both set the flag.
- [ ] Network proof: with a fake `EngineSource` spying every call, running the guide to the end while skipping the offer calls no `setPolicy` with `engine: true`, `stopAdguard` or `startAdguard`, and every data switch reads false. `stopAdguard` is called exactly once only on its click. Law 14 adds: `src/components/sieve/welcome` and `src/core/welcome.ts` never write a setting other than `startup.welcomeDone`.
- [ ] e2e: `/?source=mock&seed=1&welcome=1&engine=adguard` walks all steps at both viewports; after Finish, Home shows and a reload does not bring the guide back. Screenshots saved.

Notifications:
- [ ] `runtime.test.ts` with a fake `Desktop`: off sends nothing; on sends once per error banner and not for a toast or an info banner; focused sends nothing; a refused permission turns the setting off with a toast; a rejected `send` is a console warning and never throws into the bus.
- [ ] `pnpm rust:test` builds with the plugin registered (the capability file is validated at build).

Repo laws stay green with no exemption added: tokens, spacing ladder, no dividers, no containers, em dash, registry, core purity, normal network, unavailable. `tests/laws/normal-network.test.ts` covers the new Rust files unchanged.

## 6. UNVERIFIED (live proofs for the user; no agent runs these)

1. Real window: `/filters`, guide, dialogs, lock button, in `pnpm tauri dev` or the installed build.
2. A desktop notification appearing, and the permission behaviour, on Windows. An installed build may be required for the toast's app identity.
3. Argon2id verify time on this machine feels acceptable; `settings-lock.json` is at the expected place in the app data dir and persists across restart and across an update; uninstall leaves it behind (expected: NSIS does not clear app data).
4. The AdGuard pause from the guide, through the real Windows prompt, on a machine with AdGuard running. Same command as the Engine block, but the guide's path has never been run. `wf-coexist` may change what pausing does.
5. The first-run takeover on a truly fresh profile, and that an existing install sees it once and not again.
6. The engine honouring any of it: list selection, reports, user rules and allowlist. Nothing sends them until slice 4; the counts are mock only until then.
7. Size and build-time growth of the app from adblock-rust; measured after the first real build, not assumed.

## 7. Open questions (the user's; the default below is what gets built unless he says otherwise)

- **Q1. What the password must stand up to, and forgetting it.** Default: a UI gate with the hash in the user's app data; it stops someone at the open app, not someone with file access to the account. A real boundary needs the hash and the check in the engine under admin-only ProgramData, which is an engine change outside this stream. Forgotten password: no in-app reset; deleting `settings-lock.json` clears it, documented in `docs/conventions.md` and not shown in the app, because showing it to the person being locked out defeats the lock.
- **Q2. Does the lock cover turning things off?** Default: yes for every settings write, including the master switch, per-app Off and the engine switch, because "owner controls the settings". Left open while locked: tray and pill Pause and Resume (they write no setting), Quit, and the Start menu "Sieve - restore network" shortcut and uninstall, so nobody can be stuck with a broken network behind a password. If he wants turning off to need no password at all (the fail-open reading), it is one condition in `guard`.
- **Q3. Log hidden behind the lock.** Default: yes (D11).
- **Q4. Plan 1.5 says the first run asks once with "Filter all traffic".** This spec says the guide never changes the network, and those data switches and their live checks do not exist yet. Default: not included; slice 6 adds it as one step.
- **Q5. Rows left out.** Host drill-down (54), Support links (72, needs a public URL), About (73, may belong with `wf-updates`). Default: not built here.
- **Q6. A fourth top-level nav item.** Default: "Filters" in the top bar. The alternative is inside Settings; the screen would move with no change to its parts.

## 8. Ordered implementation

Commit per step with explicit paths, each message ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Run the suites a step touches before committing. Read `node_modules/next/dist/docs/01-app/02-guides/static-exports.md` before step 5; the conventions' static export rules apply (`/filters/` is a plain page, query strings via `window.location.search`).

1. **Core and registry.** `rules.ts`, `filter-lists.ts`, `lock.ts`, `welcome.ts`, `desktopWorthy`, the registry additions, `formatValue` noun, both fixtures. Unit tests first (the failing test for each behaviour). Update the registry law for the new element shapes. `pnpm test`.
2. **Rust.** `filters.rs` and `lock.rs` with their tests, `lib.rs`, `Cargo.toml`, the notification plugin and capability. Pick current stable `argon2` and plugin versions at least two weeks old, and read the `adblock` crate's `FilterParseError` for `friendlyRuleReason` from the local registry. `pnpm rust:test`, `pnpm rust:lint`.
3. **Data seams and runtime.** Wire types and parsers, sources, mocks, `lock-controller.ts`, `bindLock`, `bindNotifications`, query options, `Desktop.notifications`. Law 13 and law 14 (the parts not about components). `pnpm test`.
4. **Write gate.** `guard` in `useSetting`, `useEngineActions`, `useSettingsView`; `lockOf` password kind; `UnlockDialog` mounted in `AppShell`; the writer tests. Every existing test must stay green unchanged except for fakes gaining the new `Desktop` member.
5. **Filters screen.** Route, page, catalogue, groups, editor, `DomainList`. Component tests with degraded data.
6. **Password UI.** `PasswordBlock` in the new section, `PasswordDialog`, `LockButton`, `LockGate`.
7. **First-run guide.** `WelcomeGate`, `WelcomeScreen`, the network proof test.
8. **Notifications UI.** The row works through the registry; the toggle's permission path.
9. **e2e.** New specs, existing specs' counts and page lists, then the full run under the lease. Look at the screenshots at both sizes against `docs/conventions.md` sections 4 and 5 and the flat rules before calling it done. Kill anything you started, by tree.
10. **Docs.** Conventions and the parity plan's Now column. Full suites one last time. Report per criterion in section 5 with evidence, and list section 6 as UNVERIFIED.

Merge notes for the orchestrator: shared files are append-only as listed in section 4; `<LockGate>` wrap for the log route after `wf-app-log`; `filterPolicy` against whatever `wf-domain-policy` defines; `welcomeAdguard` and the guide's stop call against `wf-coexist`'s pause; `tests/e2e/settings.spec.ts` row count and rail labels will need summing with other streams' keys; `sieve-filter`'s `rules.rs` public API (`compile`, `reports`, `ListText`) must survive `wf-domain-policy` and `wf-content`.
