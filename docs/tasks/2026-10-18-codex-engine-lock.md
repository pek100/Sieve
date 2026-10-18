# Task: lock engine-dependent switches when the engine cannot take the policy; "Dev build" label

## Why (live, 2026-10-18)

The user flipped Settings > Filtering > "Route traffic through the engine" (`filtering.engine`) ON in the
DEV copy of Sieve (`pnpm tauri dev`, `src-tauri\target\debug\sieve.exe`). The engine refuses that copy by
design (the pipe client check only accepts `sieve.exe` from the install folder), so the switch flipped in
the UI but never reached the engine: its `status.json` kept `policy.engine: false`, and the live check
failed. The Engine block said "This copy of Sieve is not the installed one", but the switch itself looked
fully working, and the user could not tell the dev window from the installed one.

## Start from the partial work

A previous agent got partway and was interrupted. Its uncommitted diff is in
`docs/tasks/2026-10-18-engine-lock-partial.patch` (9 files: setting-row.tsx, use-settings-view.ts,
engine.ts and its test, registry.ts, engine-controller.ts and its test, tests/laws/registry.test.ts, and a
new `src/components/sieve/settings/engine-lock.test.tsx`). Apply it with `git apply`, read it critically,
keep what is right and finish the rest. It is unreviewed: do not trust it blindly.

## Read first

docs/conventions.md; src/core/settings/registry.ts (the `filtering.engine` dataSwitch); src/core/engine.ts
(enginePhase, including `refused`); src/data/engine-controller.ts (syncPolicy); the Settings screen's
Lock mechanism (src/components/sieve/settings/*, use-settings-view.ts); engine-card.tsx;
src/components/sieve/shell/wordmark.tsx and top-bar.tsx. AGENTS.md: read the relevant guide in
node_modules/next/dist/docs/ before writing Next code.

## Build, derived from facts (no hardcoded keys in components)

1. A data switch whose effect needs the engine (give the registry entry an attribute such as
   `needsEngine: true`) is LOCKED whenever the engine cannot take the policy: the phases not_installed,
   not_running, refused, incompatible, unreadable and checking. It uses the existing Lock mechanism, with a
   one-line reason derived from the phase. For `refused` the reason is: "This copy of Sieve is not the
   installed one, so it cannot control the engine. Open Sieve from the Start menu." The switch shows the
   value IN FORCE (the engine's `policy.engine` when known), never the user's unsent wish.
2. While locked, no `setPolicy` is ever sent. A stored value from an old settings file is left alone until
   the engine can take it, and the row shows the engine's real state.
3. A small "Dev build" label next to the wordmark in the top bar, shown only in non-release builds. Derive
   it from a build-time fact that survives the static export (`process.env.NODE_ENV` at build time, or a
   NEXT_PUBLIC_ variable set by the dev script). Verify how Next inlines it in a static export by reading
   the Next docs. Keep it flat UI (no pill or container if avoidable), aligned with the wordmark, tokens
   only. It must never show in `pnpm build` output.
4. Tests:
   - controller: phase=refused locks the switch and a flip attempt sends no setPolicy;
   - component: the lock reason is shown;
   - law: every registry entry with `needsEngine` is locked in every non-ready phase (derive the set from the
     registry);
   - the dev label: present in a dev render, absent from a production render (a unit test with the env
     stubbed, plus a check that the built `out/` HTML does not contain the label text).
5. Update docs/conventions.md.

## Run

`pnpm check` (typecheck, lint, Vitest), `pnpm rust:test` and `pnpm rust:lint` if src-tauri is touched.
Report exact counts. If `pnpm check` first fails with `LayoutProps` not found, run `pnpm exec next typegen`
once.

## UNVERIFIED (list in your report; the Claude verifier runs these)

- `pnpm e2e` (Playwright, needs the GPU lease and a browser): add or update an e2e spec for
  `?engine=refused` showing the switch disabled with the reason, but do not run it.
- the dev label in the real Tauri window.

## Limits

No em dash U+2014 anywhere. Do not run pnpm tauri dev/build, open windows, install anything, elevate,
touch E:\Sieve, its service, network settings or AdGuard. Never commit `features = []` churn in
src-tauri/Cargo.toml.
