# Sieve conventions

How this repo does things, as built by the foundation (2026-10-17). The plan (`docs/plans/2026-10-17-parity.md`) says what to build; this file says how. The look comes from `docs/research/2026-10-17-parity/design-language.md`. If code and this file disagree, fix one of them in the same commit.

## 1. Stack (fixed by the user, versions as installed)

| Layer | What | Version |
|---|---|---|
| Shell | Tauri v2 (Rust 2024 edition, feature `tray-icon`), plugins `store`, `dialog`, `autostart`; `rusqlite` (bundled) for history | tauri 2.12, cli 2.12, rusqlite 0.40 |
| UI | Next.js App Router, `output: "export"` to `out/`, `trailingSlash: true` | next 16.4.2, react 19.3 |
| Styling | Tailwind CSS v4 (CSS-first config, Turbopack loader), shadcn/ui style `radix-nova` | tailwindcss 4.3, shadcn 4.21 (dev dep) |
| Icons, charts | lucide-react; Recharts 3 through `src/components/ui/chart.tsx` | |
| Fonts | bundled, never fetched: `@fontsource-variable/inter`, `@fontsource/jetbrains-mono` (400, 500), `@fontsource/instrument-serif` (400 italic) | |
| Tests | Vitest 5 + jsdom + Testing Library; Playwright 1.61.0 (pinned: it uses the Chromium build already cached on this machine, `chromium-1228`) | |
| Package manager | pnpm 11 only | |

Next 16 differs from older Next. Before touching Next APIs read the guide in `node_modules/next/dist/docs/` (see `AGENTS.md`). Static export rules that bite: no server actions, no route handlers that read the request, no dynamic `[param]` routes without `generateStaticParams`. Deep links use the query string instead (`/apps/?app=<key>`). `useSearchParams` in a page needs a `<Suspense>` boundary or the build fails; the runtime reads `window.location.search` itself, so prefer that.

## 2. Layout

```
src/app/                    routes. page.tsx files are thin: compose components, no logic
  layout.tsx                mounts <AppShell> once (runtime, theme, top bar, toasts)
  globals.css               Tailwind entry: imports, @theme mapping, state layer CSS
src/styles/tokens.css       every design value (the only file allowed colour literals)
src/components/ui/          shadcn primitives, owned by us, already restyled to tokens
src/components/sieve/
  primitives/               state-layer, icon-button, icon-tile, segmented
  shell/                    app-shell, top-bar, page, bento-grid, card, empty-state, status-chip,
                            master-switch, theme-menu, window-controls, wordmark, notice-toaster
  <area>/                   one folder per screen area: home/ (S2), apps/ (S3), ...
src/core/                   pure TS: store, policy, apps, routes, notices, settings/
src/data/                   the data seam: protocol, source, mock-source, tauri-source, poller,
                            settings-store, prng, fixtures/
src/hooks/                  React bindings: runtime, sieve-provider, use-sieve, use-theme, use-hydrated
src-tauri/src/              lib.rs (builder), commands.rs, protocol.rs, netstat/ (S1)
tests/laws/                 repo-wide law tests (run by `pnpm test`)
tests/e2e/                  Playwright specs (run by `pnpm e2e`)
scripts/serve-out.mjs       static server for out/ (port 3417, 127.0.0.1 only)
```

Import direction: `app -> components -> hooks -> data -> core`.
- `src/core` imports only from `src/core`, plus `import type` from `@/data/protocol`. No React, Next, Tauri, DOM, `Date.now`, `new Date()`, `Math.random` (law 5). Time inside a derivation is the newest snapshot's `t`.
- `src/data` may import `src/core` (for example `isActiveFlow`).
- Components read data only through hooks (`useSieve`, `useSetting`, ...), never by importing a source or the store directly.

## 3. Seams (what exists, where to plug in)

| Seam | Files | Contract | Law test |
|---|---|---|---|
| Protocol v1 (B1) | `src/data/protocol.ts`, `src-tauri/src/protocol.rs`, fixture `src/data/fixtures/snapshot-v1.json` | `Snapshot {v:1, t, processes[], flows[]}`; `parseSnapshot(unknown)` validates and throws `ProtocolError`. `FLOW_STATES` (TS) and `FLOW_STATE_NAMES` (Rust) list the wire names in MIB_TCP_STATE order plus `none`. Changing the shape bumps the version and the fixture in one commit. | `tests/laws/protocol.test.ts` (fixture, version and state names agree with Rust); Rust `protocol::tests` (fixture round trip, names) |
| Source (B2) | `src/data/source.ts` | `SieveSource { kind; sample(): Promise<Snapshot>; history(query: HistoryQuery): Promise<History> }`. `sourceOptions({search,isTauri})`: Tauri when `__TAURI_INTERNALS__` exists, else mock; `?source=mock` forces the mock; `?seed=<n>` (default 1); `?scenario=steady\|busy\|empty\|error`. A Tauri error is shown as an error, never replaced by mock data. | `src/data/source.test.ts` |
| Mock source | `src/data/mock-source.ts`, `prng.ts` | 18 plausible apps (`MOCK_APPS`) plus System (pid 4) and one hidden `pid <n>`; flows start, persist, pass through `time_wait`, end; documentation IP ranges only; `history(query)` answers like the Rust store over 4 weeks, under the same grain retention (`mockHistory`). Content depends on seed and tick count, never on the clock (`now` is injectable). | `src/data/mock-source.test.ts` |
| Tauri source | `src/data/tauri-source.ts` | `invoke("net_snapshot")` then `parseSnapshot`; after each good sample `history_record` with per-app active flows (`historyRecord`, identity from `tickCounts`); `history(query)` is `history_buckets` then `parseHistory`. A failed write never fails the sample; the next history read reports it. | `src/data/tauri-source.test.ts`, Rust `netstat::tests` |
| History (row 77) | `src/core/history.ts`, `src-tauri/src/history/mod.rs`, wire types in both `protocol` files, fixture `src/data/fixtures/history-v1.json` | SQLite `history.sqlite3` in the app data dir. Every sample is added to its minute, hour and day bucket in one transaction (`samples` n per bucket, `app_flows` per app); each grain is pruned past `GRAINS[i].keepMs` (2 d, 35 d, 400 d). Schema in `PRAGMA user_version` (v1); a newer file is refused, never rewritten. Absent is not zero: a bucket with no samples means Sieve was not sampling. `periodQuery(ms, to)` picks the finest kept grain and at most `MAX_POINTS` buckets; `historySeries` shares `rankSeries` with the live chart; `hourActivity` feeds the heatmap. Home windows 24 h, 7 d, 14 d read history (KPIs and top apps stay live). | Rust `history::tests`; `src/core/history.test.ts`; protocol law (grains, fixture); `tests/e2e/history.spec.ts` |
| Desktop (tray, startup) | `src/core/tray.ts`, `src/data/desktop.ts`, `bindDesktop` in `src/hooks/runtime.ts`, `src-tauri/src/tray.rs` | `runtime.desktop` is null in the browser and in tests (inject a fake `Desktop`). The tray holds no logic: Rust emits `tray-action` (`{kind:"pause",minutes}` or `{kind:"resume"}`) and the window runs `poller.pauseFor` / `poller.resume`, the pause pill's actions; the window sends `trayState(phase, pausedUntil)` back through `tray_set_state` (tooltip, enabled items, dimmed icon). Open and Quit are Rust's. Launch at startup follows the setting `startup.launchAtLogin` (default off, `desktopOnly`): reconciled on load, applied on change, a failure is a toast. | `src/core/tray.test.ts`, `src/hooks/runtime.test.ts`, `src/hooks/sieve-provider.test.tsx`, protocol law (event and action names), Rust `tray::tests` |
| Settings view | `src/components/sieve/settings/*`, `src/core/settings/transfer.ts` | Rendered from `REGISTRY` and `SECTIONS`: rail plus a 720 px column, one row per key with its control chosen by kind. Search over key, label, help, section and options. Export writes changed values only; import and reset to defaults show a change preview, go through `settings.replace` and toast with Undo; a locked data switch is never imported on. A row is locked by `useSettingsView().lockOf`: data switch until its live check passed, `desktopOnly` outside Tauri, `requires` while that switch is off. | `settings.test.tsx`, `transfer.test.ts`, `tests/e2e/settings.spec.ts` |
| Poller | `src/data/poller.ts` | The only store writer and the only cadence owner. `start, stop, pauseFor(min), resume, setIntervalMs, dispose`. setTimeout chain; a failed sample sets `status.error` and keeps snapshots; a stopped generation drops in-flight results. Clock injectable (`Clock`). | `src/data/poller.test.ts` |
| Store | `src/core/store.ts` | `SieveState {source, intervalMs, snapshots (oldest first), capacity, status {running, pausedUntil, error}}`. Ring size = `capacityFor(longest declared window, interval)`. A consumer that reads history calls `store.declareWindow(ms)` (keep the undo for unmount). `phase(state)` derives `starting\|live\|paused\|off\|error`; `newest(state)`. | `src/core/store.test.ts` |
| Settings (B5) | `src/core/settings/registry.ts`, `document.ts`, `migrate.ts`; storage `src/data/settings-store.ts` | Every setting is one `REGISTRY` entry. Stored doc `{schema, values}` with non-default values only; wrong-shaped values read as the default; unknown keys kept. Browser: `localStorage["sieve.settings"]`; Tauri: plugin-store `settings.json`. Writes wait for the first load. | `tests/laws/registry.test.ts`, `src/data/settings-store.test.ts` |
| Policy (B4) | `src/core/policy.ts` | `LEVELS = off < watch < sieve`, `DEFAULT_LEVEL = watch`, `LEVEL_REQUIRES = {sieve: "filtering.dns"}`. `ceiling(switchOn, checkPassed)`; `effectiveLevel(requested, ceiling) = min`. In React: `useLevelCeiling()`. | `src/core/policy.test.ts` |
| Apps (B3 starter) | `src/core/apps.ts` | `groupApps(snapshot)`: identity = ProductName, else exe stem, else process name; key is lower case. `category(app, pinned)`: pinned -> `mine`, all exes under `X:\Windows\` or none readable -> `system`, else `apps`. `isActiveFlow` (has a remote, not listening). `isSieved(app, effective)`. | `src/core/apps.test.ts` |
| Notices (B7) | `src/core/notices.ts`, renderer `shell/notice-toaster.tsx` | `runtime.notices.push({kind, text, action?, surface?})`. Never call `toast()` from sonner directly. Banners (`surface: "banner"`) render in the Home slot `home/home-banner.tsx`, mounted in `<Page notice>` (inside the header row at 1280+, so it costs no height; its own line below that). The pause pill pushes one and dismisses it when sampling resumes; the banner has no action of its own because Resume is the pill. | `src/core/notices.test.ts` |
| Home derivations (S2) | `src/core/series.ts`, `kpis.ts`, `heat.ts` | `buildSeries(snapshots, {windowMs, intervalMs, previousSlots})`: active flows per app per bucket, top `SERIES_COUNT` (6) by window total, rest in `OTHER_KEY`; slots stick while an app stays in the top set (`createSlotKeeper`). At most `MAX_POINTS` (300) buckets. `stackSeries(model, hidden)`. `kpis(window, levelOf)`: sieved apps with connections (`isSieved`: level watch or sieve and an active flow), active connections, remote hosts, listening ports, each with a delta against the window start. `heatGrid(hourActivity(history))`: 7 x 24, Monday first, local time, 4 steps, plus `first` (earliest bucket). `heatCaption(grid, range)` says how far back it goes from the buckets returned ("Last 4 weeks" or "Since ..."), never from the source kind. | `series.test.ts`, `kpis.test.ts`, `heat.test.ts` |
| Routes | `src/core/routes.ts` | `ROUTES` is the nav, in order. A slice that adds a screen appends exactly one entry (`href` with leading slash, `label`, `icon` key; add the icon to the map in `top-bar.tsx` if new). | `src/core/routes.test.ts` |
| Shell | `src/components/sieve/shell/*` | See section 5. | `shell.test.tsx`, `tests/e2e/shell.spec.ts` |

Runtime wiring: `src/hooks/runtime.ts` builds one `Runtime {isTauri, source, store, poller, settings, notices, passedChecks, clock, desktop}` per window (`createBrowserRuntime`, safe during prerender). `SieveProvider` mounts `bindSampling` (the poller follows `sampling.enabled` and `sampling.intervalMs`) and `bindDesktop` (tray and launch at startup); unmounting undoes both. History queries take "now" from `runtime.clock`, never `Date.now`. Tests build their own with `createRuntime({source, settings: memoryBackend(), clock?})` and pass it to `<AppShell runtime={...}>` or `<SieveProvider runtime={...}>`.

Hooks: `useRuntime()`, `useSieve(selector)` (rerenders on every store change; derive inside the selector, pass a module-level function when it is costly), `useSetting(key) -> [value, set]`, `useLevelCeiling()`, `useNotices()`, `useResolvedTheme()`, `useHydrated()` (false during prerender and hydration; use it before rendering anything that differs between server and client, such as Tauri-only controls).

## 4. Tokens and styling

- All values live in `src/styles/tokens.css` as role variables, dark under `:root, :root[data-theme="dark"]`, light under `:root[data-theme="light"]`, both with the same names (law checks). `<html data-theme>` is set by `useThemeSync` from the setting `appearance.theme` (system, light, dark; default dark).
- Tailwind's default colour palette is removed, so only role utilities exist:
  - surfaces `bg-bg bg-surface-1 bg-surface-2 bg-surface-3 bg-inset bg-scrim`, lines `border-outline border-outline-strong`
  - text `text-on-surface text-on-surface-muted text-on-surface-faint`
  - accents `primary on-primary blocked on-blocked warning info` (as `bg-*`, `text-*`), containers `bg-mint-container text-on-mint-container` (also peach, lilac)
  - chart `series-1` to `series-6`, `series-other`; heatmap steps as variables `bg-(--heat-mint-0)` to `-3` (also lilac, peach); `bg-track`, `bg-selected` (accent at 16%)
  - shadcn names (`bg-card`, `bg-popover`, `text-muted-foreground`, `ring`, `destructive`, ...) are aliases of the roles, never separate values.
- Type: `text-display text-title-lg text-title text-kpi text-body text-body-strong text-label text-caption text-mono` (size, line height and weight together). Numbers get `tabular` (class) or `data-numeric`. Hosts and paths: `font-mono text-mono`. The serif (`font-serif italic`) appears at most once per screen, only through `EmptyState` or an onboarding hero.
- Radii: `rounded-xs` 4 (cells, bar ends), `rounded-sm` 8 (icon tiles, inputs), `rounded-md` 12 (menus, tooltips), `rounded-lg` 16 (cards), `rounded-xl` 24 (dialogs), `rounded-full` (buttons, chips, switches, segmented, search).
- Elevation: `shadow-l1` cards (includes the 5% rim), `shadow-l2` raised tiles and thumbs, `shadow-l3` menus and tooltips, `shadow-l4` dialogs and toasts, `shadow-inset` search and chart wells. The only glow is the master switch (`animate-breathe`).
- Spacing: only the ladder 4/8/12/16/20/24/32/40, that is Tailwind steps `0 1 2 3 4 5 6 8 10` for padding, margin and gap in `src/components/sieve` and `src/app` (law). Sizes (`h-14`, `size-9`) are free.
- Motion: `duration-(--motion-fast|base|emph-in|emph-out|chart)` with `ease-standard`, `ease-emph-in`, `ease-emph-out`. Under `prefers-reduced-motion` `--motion-chart` and `--motion-ripple` become 0, ripples are not spawned and pulse and shimmer stop. Live chart updates never re-animate from zero.
- Breakpoints: `two:` at 960 px and `three:` at 1280 px (plus `max-[640px]:` for the narrow browser mock). Do not use `md:`/`lg:` for page layout.
- Banned (law 1): colour literals outside tokens.css (hex, rgb, hsl, oklch, ...), `dark:` classes anywhere in `src`, `var(--x)` of a variable nobody defines.
- Class merging: always `cn` from `@/lib/utils` (ui primitives too, never `from "cn"` directly). It is `createCn` with the type roles registered as font sizes; without that, `text-label text-on-surface-muted` lost the size and filled buttons lost `text-on-primary` (`src/lib/utils.test.ts` keeps the list equal to the `--text-*` roles in globals.css).
- Series colours by slot: `seriesTone(slot)` in `home/series-tone.ts` spells out `fill-series-N`, `bg-series-N/20`, ... (never build `var(--series-${n})`, the variable law cannot see it).

## 5. UI placement and components

- A screen is `src/app/<route>/page.tsx` that renders `<Page title action? notice? fill?>` with a `<BentoGrid>` of `<BentoItem span="third|two-thirds|half|full">`. Spans: at 1280+ third 4, two-thirds 8, half 6; at 960 to 1279 third and half 6, two-thirds 12; below 960 everything 12. Page header row is 64 px; outer padding 24 px (16 below 640).
- Every block of content is a `<Card title icon? tone? action? state? dense?>`. `state` is `{kind:"ready"}` (default), `{kind:"loading"}` (skeleton), `{kind:"empty", line, body?, action?}`, or `{kind:"error", message}`. Each card has its own error boundary (`CardBoundary` is exported for blocks that are not one Card, such as the Home KPI tiles). Card padding is 20 (16 with `dense`). When title and action do not fit on one line, the action wraps under the title.
- One status chip per window, in the top bar. A screen does not repeat it. Under 480 px it shows the one-word phase, never a bare dot.
- `<Page fill>` makes the page exactly window-tall at 1280+, so a `three:flex-1` grid takes the height left under the header. Do not subtract sibling heights in a calc.
- Live charts: the Home chart (`home/activity-chart.tsx`) is hand-drawn SVG, not Recharts, because Recharts remounts its area paths on every data change. x is absolute time in units of the whole window choice; the view span (`viewMs`, which doubles as data accumulates, from 16 samples) lives only in the plot group's transform (`translateX` slides a bucket per tick, `scaleX` rescales on a view step), so path nodes and existing vertices survive both. Key the chart by the window choice only, never by anything that changes on a tick. `d` morphs only when the bucket times did not change (legend toggle). Use Recharts through `ui/chart.tsx` for static charts.
- Pressables: shadcn `<Button>` (pill; variants `default` filled mint, `secondary` tonal, `outline`, `ghost` text, `destructive` tonal pink, `link`), `<IconButton label>` (round 36, `label` is required and becomes `aria-label`, optional `badge`, `toggled`), `<Segmented items value onChange label>` for in-page choices (Day/Month/Year, off/watch/sieve), `<SegmentedNav>` only in the top bar. Anything custom and pressable is `relative overflow-hidden` with `<StateLayer />` as its last child.
- Icons: lucide-react, `strokeWidth={1.75}`, sizes 16/20/24, inside `<IconTile size={32|40} tone>` in rows and headers. A missing app icon is a monogram on the app's series tint (S2/S3 build it).
- Copy: sentence case, plain words, no em dashes. Never claim filtering that is not happening: counters say connections, hosts or ports while `filtering.dns` is off. One warm serif line per screen at most.
- Accessibility: every icon-only control has an accessible name (shell test checks the shell); dialog titles may be `sr-only`; status text never relies on colour alone (the status chip has text and `data-phase`).

## 6. Settings and data switches

- Add a setting: one entry in `REGISTRY` with `kind` (`enum`, `boolean`, `number`, `map`, `list`, `dataSwitch`), `section` equal to the key prefix (`appearance.theme` is in `appearance`), `label`, `help`, `default`, optional `requires`. Adding a key with a default does not bump `SETTINGS_SCHEMA`; renaming or retyping one does, with a step in `migrate.ts`.
- Anything that changes traffic or the system is a `dataSwitch`: default `false`, `liveCheck: "live_<what_it_proves>"` naming an `#[ignore]`d Rust test (or Playwright spec) of the same name. Today there is one: `filtering.dns` -> `live_dns_filter_resolves_blocked_domain` (the test is `dns::engine::tests::live_dns_filter_resolves_blocked_domain`, run with `cargo test --manifest-path src-tauri/Cargo.toml --lib -- --ignored live_dns`; in the app the same proof is `dns_self_check` against the running proxy). A level or feature that needs it reads `useLevelCeiling()` or `requires`; a passed live check is recorded in `runtime.passedChecks` (nothing records one yet, so the ceiling is `watch`).
- What needs a switch: DNS proxying, a system or local HTTP proxy, WFP or firewall rules, certificate installs, anything writing outside the app's own data dir. What does not: reading the TCP/UDP owner-pid tables, process image names and version info (read only, no admin), the settings file, the file dialog.
- Never needed: admin rights, drivers, system proxy, DNS or firewall changes in the foundation or the three slices.
- A setting only the desktop app can apply (today `startup.launchAtLogin`, the current user's Run entry through the autostart plugin, written only when the user turns it on) is `desktopOnly: true`; the browser shows it locked with the reason.
- Map and list settings declare their element shape (`of`), so a corrupt stored `apps.levels` or `apps.pinned` reads as the default. UI code never names a data switch key: it reads `LEVEL_REQUIRES` or `requires` (registry law).

## 7. Tests and commands

Run in PowerShell from the repo or worktree root.

| Command | What |
|---|---|
| `pnpm install` | install (first time per worktree) |
| `pnpm dev` | Next dev server, http://localhost:3000, browser mode with the mock source |
| `pnpm build` | static export to `out/`, then `scripts/flatten-segments.mjs` (Next 16.4.2 writes nested segment prefetch files as `__next.apps/__PAGE__.txt` but the router fetches `__next.apps.__PAGE__.txt`; the script copies them to the flat name so no static host, Tauri included, answers 404) |
| `pnpm typecheck` | `tsc --noEmit` |
| `pnpm lint` | ESLint (next core-web-vitals + typescript, React compiler rules on) |
| `pnpm test` | Vitest: `src/**/*.test.ts(x)` and `tests/laws/**` |
| `pnpm check` | typecheck + lint + test: the gate before any merge |
| `pnpm e2e` | `pnpm build` then Playwright; serves `out/` on 127.0.0.1:3417 via `scripts/serve-out.mjs`; projects `desktop` 1280x800 and `mobile` 375x812; screenshots in `test-results/screens/` |
| `pnpm rust:test` | `cargo test --manifest-path src-tauri/Cargo.toml` |
| `pnpm rust:lint` | `cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings` |
| `pnpm tauri dev` | the real app (a person or a live check only, never in a slice run) |

- Run e2e through the machine's GPU lease, even with `--disable-gpu`, and launch pnpm through `cmd /c` (the lease cannot start the pnpm shim directly):
  `powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-e2e -NeedMiB 300 -- cmd /c pnpm e2e`
  The lease runs the tree in a kill-on-close job, so the static server and Chromium die with it.
- Redirect long output to a file (`cmd /c "pnpm test > %TEMP%\out.txt 2>&1"`) instead of piping into `Select-Object -First`.
- Unit and component tests sit next to the code as `*.test.ts(x)`. Component tests build a runtime with `createRuntime({ source: createMockSource({ seed: 1 }), settings: memoryBackend() })` and mock `next/navigation` (`vi.mock("next/navigation", () => ({ usePathname: () => "/" }))`). Time-dependent logic takes an injected `Clock` (see the fake clock in `poller.test.ts`).
- e2e specs open `/?source=mock&seed=1` (or `&scenario=empty|error|busy`), assert roles and `data-phase`, check no console errors and no horizontal scroll at 375, and save a screenshot per project.
- Rust tests live in `#[cfg(test)]` modules. A test that needs the real machine is `#[ignore]` and named `live_*`; its name is the live check (`cargo test --manifest-path src-tauri/Cargo.toml -- --ignored live_`).
- The five laws (`tests/laws/`): 1 tokens (no colour literals outside tokens.css, no `dark:`, spacing ladder, no undefined variables, both themes define every role); 2 no em dash in `src`, `src-tauri/src`, `docs`, `tests`, `scripts`; 3 protocol parity with Rust and the fixture; 4 registry (data switches off with a `live_` check, `requires` valid, defaults valid, storage only through the settings seam); 5 core purity.
- Every bug found becomes a test. A slice adds its own tests and keeps every existing one green.
- Class merging: always `cn` from `@/lib/utils` (also inside `src/components/ui`). It is configured with the type scale (`text-label`, `text-body`, ...), so a text colour and a type size in one `cn` call both survive; the bare `cn` package read the sizes as colours and dropped one (`src/lib/utils.test.ts` keeps it that way).

## 8. Rust side

- `lib.rs` registers plugins and `generate_handler![...]`; each command lives in `commands.rs` and is `async`, running blocking work in `tauri::async_runtime::spawn_blocking`; it returns `Result<T, String>`.
- Module errors are `thiserror` enums (`NetstatError`), turned into strings only at the command boundary. No `unwrap`/`expect` outside tests; clippy runs with `-D warnings`.
- Only read calls to Windows: S1 adds the `windows` crate features it needs in `Cargo.toml`. No admin, no drivers, no writes to system state.
- Capabilities (`src-tauri/capabilities/default.json`) grant window controls, `store:default` and `dialog:default`. Add a permission only with the command or plugin that needs it.
- Each worktree keeps its own `src-tauri/target` (the default). First build is about 2 minutes.

## 9. Process and git

- Kill every process you start: `Get-Process node, cargo, chrome -ErrorAction SilentlyContinue` after a run; stop by tree (`taskkill /T /F /PID <pid>`) anything you launched. Playwright under the lease cleans itself up.
- No GPU work in this repo. The only browser is the e2e Chromium, under the lease.
- Commit per step with explicit paths (`git add -- <paths>`, never `git add -A`); messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Slices own the files the plan lists for them; shared files (`routes.ts`, `REGISTRY`) get append-only edits.

## 10. Known gaps (foundation)

- `pnpm tauri dev` was not run (tests only); window controls, drag region, plugin-store and dialog are compiled and permissioned but not looked at. CSP is `null` until someone checks Next's inline scripts under a strict policy.
- The light theme chart series (`--series-1` to `-6` in light) and light `--blocked` are proposals, not measured; dark `--on-surface-faint` contrast is unverified. All motion values are proposals.
- No inline theme script: a user who picked light sees the dark default for one frame on load.
- `groupApps` follows the plan's identity rule (ProductName first). Windows' own exes share one ProductName, so explorer, svchost and SearchHost group as one app, "Microsoft Windows Operating System" (visible in the mock). S2/S3 should decide whether system apps group by exe stem instead.
- `useSieve` rerenders every consumer on every store change (1 Hz by default). Home selects `s.snapshots` (same array until a new sample) and caches per-snapshot counts in a WeakMap, so a status change does not recompute the chart.
- S2 kept the ProductName identity: the Windows exes show as one Home series, "Microsoft Windows Operating System". The exe-stem decision for system apps is left to S3 (Apps).
- Home's Session window keeps at most 2 h (`SESSION_MAX_MS`), and the 1 h and Session windows hold every snapshot in the ring (about 3600 and 7200 full snapshots at 1 s). Memory at those sizes is not measured; a compact per-tick count history would be the fix if it is too much.
- Wave 2: the tray, its dimmed icon, launch at startup and the SQLite file were not looked at in a live window (no `pnpm tauri dev` in a slice run); they are covered by Rust unit tests and by TS tests against a fake `Desktop`. The paused banner derives from `status.pausedUntil`, so it is right after navigating and when the tray pauses.
- Apps screen (S3): levels and pins change only through the reducers in `src/core/apps-actions.ts` (`setLevel` clamps to the ceiling, reads go through `levelOf`); the screen hook is `src/components/sieve/apps/use-apps.ts`, the deep link `?app=<key>` lives in `use-app-param.ts`. S3 kept the ProductName identity rule, so Windows' own exes still show as one System app. The reason a level is locked is the disabled item's `title` (native tooltip) plus a visible line on the card and in the sheet; `Segmented` has no Radix tooltip slot for a disabled item.
