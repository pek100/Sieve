# Engine locks and development label: executor evidence

The partial patch was applied with `git apply docs/tasks/2026-10-18-engine-lock-partial.patch` and reviewed. Policy eligibility now derives from a successful probe, a running service and an accepted handshake with Status. The phase explanations supply the lock text. Settings uses the registry attribute and displays the known policy while locked, leaving stored wishes alone. The wordmark uses the build-time environment, and the production build checks exported HTML for the label.

## Commands and observed results

Every Node command below used this PowerShell prefix:

```powershell
$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH
```

- `node node_modules/typescript/bin/tsc --noEmit` initially reported `Cannot find name 'LayoutProps'`. `node node_modules/next/dist/bin/next typegen` printed `Types generated successfully`. The subsequent `node node_modules/typescript/bin/tsc --noEmit` completed without diagnostics.
- `node node_modules/eslint/bin/eslint.js` completed without diagnostics before the temporary probe config was created. A later run with that scratch config present reported an anonymous-default-export warning in the scratch config only. After removing the scratch file, the final `node node_modules/eslint/bin/eslint.js` again completed without diagnostics.
- `node node_modules/vitest/vitest.mjs run` could not write its bundled config under the shared dependency junction (`node_modules/.vite-temp`, EPERM).
- `node node_modules/vitest/vitest.mjs run --configLoader runner` reported no tests and 51 worker errors (`ERR_REQUIRE_ESM` from jsdom's dependencies).
- `$env:NODE_OPTIONS = "--experimental-require-module"; node node_modules/vitest/vitest.mjs run --configLoader runner` still could not start the workers: undici's decompression module accessed an unavailable API. No dependency or runtime was installed or modified.
- `node node_modules/vitest/vitest.mjs run --config vitest.engine-probe.config.mts --configLoader runner` passed 97 tests in 17 files. This ran the core engine tests, controller tests, all repository laws, and the wordmark's development and production static renders. It did not run DOM component tests. The temporary config was exactly the following, and was removed afterward:

```typescript
import config from "./vitest.config.mts";

export default {
  ...config,
  cacheDir: "./.next/vitest-engine-probe",
  test: {
    ...config.test,
    environment: "node",
    setupFiles: [],
    include: ["src/core/engine.test.ts", "src/data/engine-controller.test.ts", "tests/laws/**/*.test.ts", "src/components/sieve/shell/wordmark.test.tsx"],
  },
};
```

The unmodified `node node_modules/next/dist/bin/next build` could not resolve Next through the external dependency junction. A temporary `turbopackAdditionalRoots` attempt resolved packages but failed on font URLs that traversed outside the worktree. Widening only the build's resolution root to the common parent succeeded. No host files were edited, and the config was restored. An intermediate build caught the temporary test config's `.mts` import during typechecking; removing that scratch file allowed the build to finish.

This exact PowerShell command completed the export, flattened its segment files, and printed `Release label check: 6 HTML files, no Dev build text.`:

```powershell
$env:PATH = "C:\Program Files\cursor\resources\app\resources\helpers;" + $env:PATH; $buildConfigPath = Join-Path (Get-Location) "next.config.ts"; $buildConfigOriginal = [IO.File]::ReadAllText($buildConfigPath); try { [IO.File]::WriteAllText($buildConfigPath, $buildConfigOriginal.Replace("  turbopack: {", '  turbopack: { root: "F:/Projects/Code/Sieve",'), (New-Object Text.UTF8Encoding($false))); node node_modules/next/dist/bin/next build; $buildExit = $LASTEXITCODE; if ($buildExit -eq 0) { node scripts/flatten-segments.mjs; $buildExit = $LASTEXITCODE }; if ($buildExit -eq 0) { node scripts/check-release-label.mjs; $buildExit = $LASTEXITCODE } } finally { [IO.File]::WriteAllText($buildConfigPath, $buildConfigOriginal, (New-Object Text.UTF8Encoding($false))) }; exit $buildExit
```

`git diff -- next.config.ts` afterward was empty. `git diff --check` found no whitespace errors, only Git's line-ending conversion warnings.

The bundled Next environment and static-export guides were read with `Get-Content node_modules/next/dist/docs/01-app/02-guides/environment-variables.md` and `Get-Content node_modules/next/dist/docs/01-app/02-guides/static-exports.md`. `Select-String -Path node_modules/next/dist/build/define-env.js -Pattern 'process.env.NODE_ENV' -SimpleMatch -Context 1,3` showed the replacement choosing development for dev builds and production otherwise. The export check above verifies the resulting HTML.

## Remaining verification

- Full `pnpm check` with the normal supported runtime. The Settings DOM tests, including the new registry-derived engine-lock matrix, refused click and known-policy display tests, were written and typechecked but could not run under this sandbox's jsdom/runtime combination.
- Ordinary `pnpm build` without the temporary resolution-root accommodation, on the verifier's normal dependency layout. The export observed here used that accommodation.
- `pnpm e2e`, including the new `?engine=refused` case, deliberately not run. The verifier must use the GPU lease.
- The development label's appearance and alignment in a real Tauri window, and actual installed versus development-copy IPC behavior. No window, browser, service or network operation was started.
- Rust was untouched; no cargo tests or lint were run.
- All command sessions started for this task returned. A process-wide orphan audit through `Get-CimInstance Win32_Process -Filter "Name = 'node.exe'"` was denied access, so that audit is unverified.
- The driver creates the commit after receiving `CODEX-COMMIT.txt`; the executor does not claim a commit was created.
