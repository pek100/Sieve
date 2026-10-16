# Sieve conventions

Owner of the rules every slice follows. The plan (`docs/plans/2026-10-17-parity.md`) links here and does not repeat them. Tokens and component looks come from `docs/research/2026-10-17-parity/design-language.md`.

## Stack (fixed by the user)

- Tauri v2 (Rust) shell, Next.js App Router with `output: "export"` (static, loaded by Tauri from `out/`), React 19, TypeScript strict, Tailwind CSS v4, shadcn/ui (Radix), lucide-react icons, Recharts through the shadcn `chart` component. pnpm only.
- Fonts are bundled, never fetched at build or run time: `@fontsource-variable/inter`, `@fontsource/jetbrains-mono`, and one OFL italic serif (`@fontsource/instrument-serif`, italic 400) for the single display line an empty state may carry.
- No backend, no network calls from the app. Everything runs on the user's machine.

## Layout

```
src/app/            routes (page.tsx files stay thin: compose components, no logic)
src/components/ui/  shadcn primitives, restyled through tokens at the call site
src/components/sieve/<area>/  Sieve components, one folder per screen area
src/core/           pure TypeScript: model, derivations, policy, settings registry. No React, no DOM, no Tauri, no clock.
src/data/           the data seam: protocol.ts, source.ts, mock-source.ts, tauri-source.ts, settings-store.ts, fixtures/
src/hooks/          React bindings over src/core and src/data (useSyncExternalStore)
src/styles/         tokens.css (the only file allowed to hold colour literals), globals.css
src-tauri/          Rust: lib.rs (builder), commands.rs, protocol.rs, netstat/ (connection tables)
tests/e2e/          Playwright specs; tests/laws/ repo-wide law tests
scripts/            serve-out.mjs and other dev scripts
```

Imports go one way: `app -> components -> hooks -> core/data`. `src/core` imports nothing outside itself.

## Commands (run in PowerShell from the repo or worktree root)

| Command | What it does |
|---|---|
| `pnpm install` | install |
| `pnpm dev` | Next dev server on http://localhost:3000, browser mode, mock source |
| `pnpm build` | static export to `out/` |
| `pnpm typecheck` | `tsc --noEmit` |
| `pnpm lint` | ESLint (next config) |
| `pnpm test` | Vitest: core, data, components (jsdom) and `tests/laws` |
| `pnpm e2e` | builds, serves `out/` on port 3417 via `scripts/serve-out.mjs`, runs Playwright Chromium with `--disable-gpu`, writes screenshots to `test-results/screens/` |
| `pnpm check` | typecheck + lint + test (the gate before any merge) |
| `cargo test --manifest-path src-tauri/Cargo.toml` | Rust unit and parity tests |
| `cargo clippy --manifest-path src-tauri/Cargo.toml -- -D warnings` | Rust lint |
| `pnpm tauri dev` | the real app (human or live check only) |

Machine rules: run `pnpm e2e` through the GPU lease even though Chromium runs with `--disable-gpu`:
`powershell -NoProfile -File <tools>\procs\with-gpu.ps1 -Label sieve-e2e -NeedMiB 300 -- pnpm e2e`. Kill every node, next, cargo and browser process you start. Each worktree keeps its own cargo target dir (the default `src-tauri/target` inside the worktree).

## Data seam

- One protocol, mirrored both ends: `src/data/protocol.ts` and `src-tauri/src/protocol.rs`, both carrying `PROTOCOL_VERSION`. Fixture `src/data/fixtures/snapshot-v1.json` is parsed by a Vitest test and by a Rust test; changing the shape bumps the version and the fixture in the same commit.
- One `SieveSource` interface. `resolveSource()` picks `tauri` when `window.__TAURI_INTERNALS__` exists, `mock` otherwise, and `?source=mock` forces the mock in Tauri. A Tauri error surfaces as an error state; it never falls back to the mock silently.
- The mock is deterministic: seeded PRNG (`?seed=`, default 1), scenarios `?scenario=steady|busy|empty|error`. No `Math.random` and no `Date.now` in `src/core`; the time of a derivation is the newest snapshot's `t`.
- Real process paths in fixtures are scrubbed (`C:\Users\<user>\...`). No usernames, hostnames or IPs from this machine in committed files.

## Settings

- Every setting is one entry in `src/core/settings/registry.ts` (key, section, kind, default, label, help, optional `requires` data switch, optional `liveCheck`). Screens, search, export, import and reset are derived from the registry. No setting is declared anywhere else.
- Data switches (anything that would change traffic or the system) are registry entries of kind `dataSwitch`, default `false`, with a named `liveCheck`. A law test enforces both.
- Stored document: `{ schema: SETTINGS_SCHEMA, values: {...non-default values} }`. Missing keys read as defaults, unknown keys are kept and ignored, adding a key with a default does not bump the schema; renaming or retyping one does, with a migration in `src/core/settings/migrate.ts`.
- Storage seam: `localStorage` in the browser, `tauri-plugin-store` (`settings.json` in the app config dir) in Tauri.

## Design

- Colours, radii, shadows, spacing and motion are CSS variables in `src/styles/tokens.css`, exposed to Tailwind through `@theme`. No hex, rgb or hsl literal anywhere else in `src/`; no `dark:` variants; no raw Tailwind spacing outside the ladder (4/8/12/16/20/24/32/40).
- Dark is the default theme (`<html data-theme="dark">`); light swaps the same role names. Theme choice: system, light, dark.
- shadcn: keep behaviour, restyle at the call site with `cn()`. Buttons are pills; tonal fills over outlines; destructive is tonal pink, never solid.
- Material states: state layer overlay hover 8%, focus 10%, pressed 10% plus ripple, dragged 16%; selected is accent at 16% with accent text; disabled is 38% content. Focus ring 2 px mint, 2 px offset, keyboard only. One shared `<StateLayer>`/ripple implementation, used by every pressable.
- Motion tokens from the design language; `prefers-reduced-motion` drops ripple expansion, chart morphs and the pulse. Live chart updates never re-animate from zero.
- Every icon button has an `aria-label`. Dialog titles are `sr-only`.
- Copy: sentence case, plain words, no em dashes, never claims filtering that is not happening. Counters name what is measured (connections, hosts), not ads or trackers, while filtering is off.

## Code

- TypeScript strict, no `any`. Errors thrown, not returned as `{ok:false}`, except expected "no" answers. Render paths absorb and degrade (error boundary per card, empty and error states), everything else fails fast.
- Rust: no `unwrap` outside tests; errors as `thiserror` enums serialised to a string for the command result. No admin rights, no drivers, no writes to system state.
- Tests sit next to code as `*.test.ts(x)`; Rust tests in `#[cfg(test)]` modules. A test that needs the real machine is `#[ignore]` and named `live_*`; its name is the live check.
- Every found bug becomes a test.
- No em dashes in code, comments, copy, commits or docs (law test).
- Commits: explicit paths, message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Law tests (in `tests/laws/`, part of `pnpm test`)

1. Token law: no colour literals outside `src/styles/tokens.css`, no `dark:` classes in `src/`.
2. Em dash law: no U+2014 in `src/`, `src-tauri/src/`, `docs/`.
3. Protocol law: the v1 fixture parses on the TS side (and on the Rust side in `cargo test`).
4. Registry law: every `dataSwitch` defaults to `false` and names a `liveCheck`; every key is unique; every `requires` points at an existing data switch.
5. Core purity law: no imports of `react`, `next`, `@tauri-apps` and no `Date.now`/`Math.random` in `src/core`.
