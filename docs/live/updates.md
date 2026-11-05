# Signed updates: the live proofs (slice 13)

Everything here is yours to run, on your own machine. No agent has run any of it, and nothing below is reported as passing until you have. The offline acceptance tests are in `docs/tasks/2026-11-02-updates.md` section 5.

Until step 1 and step 2 are done the engine says `not_configured` and never fetches anything. That is the shipped state.

## 1. Your key pair

Generate it with minisign on your own machine, not in this repo. `minisign` is not installed on this machine yet.

```
minisign -G -p sieve-update.pub -s <somewhere offline>\sieve-update.key
```

- The private key stays offline: never in the repo, CI or the release host. Law 13 walks the repo for secret keys, in plain and base64 form, and fails on any file named `*.key`.
- Put the second line of `sieve-update.pub` (`RW...`) into `PUBLIC_KEY` in `engine/crates/sieve-engine/src/update/trust.rs`, replacing the placeholder. A key change later ships inside a release signed by the old key.

Sign every artefact with an exact trusted comment. Anything else is refused, including minisign's default comment:

```
minisign -Sm <file> -s <key> -t "sieve-update kind=<kind> version=<n>"
```

`<kind>` is `app`, `engine`, `resources`, `index` or `list:<id>`. `tauri signer sign` writes its own trusted comment as far as we remember, so check it before using it; `minisign -Sm` is the known-good path.

Version numbers: `app` and `engine` use `major*1000000 + minor*1000 + patch` of the Cargo version (0.2.0 is 2000). Data kinds use any rising integer.

Publish `app` for normal releases. Publish `engine` only for a fix that does not change the pipe protocol: an engine-only update whose protocol moved shuts the old app out until a reinstall.

## 2. The host and the index

Set `UPDATE_BASE_URL` in `trust.rs` (open question Q1). Redirects are not followed, so GitHub Releases would need a change first.

Serve `index.json` and `index.json.minisig`, and each artefact with its `<file>.minisig`, all from that URL:

```json
{
  "schema": 1,
  "version": 7,
  "expires_unix": 1800000000,
  "artefacts": {
    "app": { "version": 2000, "file": "Sieve_0.2.0_x64-setup.exe", "size": 12345678 },
    "resources": { "version": 3, "file": "resources-3.bin", "size": 54321 }
  }
}
```

Sign it with `-t "sieve-update kind=index version=7"`: the comment's version must equal the body's. Raise `version` on every publish and keep `expires_unix` a few weeks ahead; an expired index is reported as stale and nothing applies. `size` is the exact byte count, and the download is cut there.

Check: the real TLS fetch over the pinned socket, with Sieve's routes up and with them down, and DNS resolution of the host while the engine routes. `tls_refuses_an_untrusted_root` proves rustls's refusal in memory only, not the real chain to a real host.

## 3. The swap in the install folder

Publish an `engine` release and click Install update in Settings > Filtering.

Check:
- the staged file and `*.old` inherit the folder's lock: the new engine's start-up folder check passes (`sc query sieve-engine` shows it running, and `ProgramData\Sieve\engine\last-error.txt` says nothing new);
- `sc qc sieve-engine` and the version in the app show the new build;
- `update-pending.json` is gone, `update-state.json` holds the new version, and the `.old` file is gone;
- `update-staging` goes at the next check (the supervisor cannot delete its own running copy).

## 4. The supervisor

Check that `update-finish.exe` survives the service stopping as a detached child, and that `stop` and `start` work under the four trimmed privileges (`REQUIRED_PRIVILEGES`). Whether it inherits a sufficient token is unknown; this is the first thing to look at if the engine stops and does not come back. `update.log` in `ProgramData\Sieve\engine` has what it did. To recover by hand: `sc start sieve-engine`, or reinstall.

## 5. The real installer as SYSTEM

Publish an `app` release and install it.

Check, with `/S /UPDATE /D=<folder>` running as SYSTEM: the hooks run, icacls `/setowner` works under the trimmed token, a running `sieve.exe` is force-closed, shortcuts and the uninstall entry are written from session 0, and `TEMP` in the staging folder works for NSIS plugins. Sieve does not relaunch by itself (`/R` is never passed from session 0): open it from the Start menu.

Then check the pipe still belongs to you. `ProgramData\Sieve\engine\state.json` must hold your own SID (`whoami /user`), not `S-1-5-18`, and the unelevated app must connect and show the new version. The installer's post-install hook runs the `install` verb as SYSTEM here; the unit test `an_install_as_system_keeps_the_recorded_pipe_user` covers the decision, not this real path.

## 6. A new engine that fails

Publish an engine build that exits at start. Check that the real supervisor rolls back within about 90 seconds, that the old build runs again, that the record did not rise, and that the app says the version did not start and does not offer it again.

## 7. Plan 7.5's live acceptance

Sign a test release with your offline key, request it from the app, watch it apply; `sc qc` and the version in the app show the new one. Then re-serve an older release: it is refused.

## Known limits, stated plainly

- Power loss during a swap with a broken new engine: after that boot no supervisor exists, so nothing rolls back. The service manager restarts twice and stops, the network stays normal, and you reinstall.
- A rollback blocked by a locked file (usually an antivirus scan) keeps every `.old` file and retries, and the app says the previous version could not be restored yet. If the new engine cannot start and the file is still locked after an hour, retries stop until an engine runs: the network stays normal, and you reinstall.
- A health report followed by a crash seconds later is not rolled back. The existing crash-loop stop handles it, fail open.
- `.old` files left by a reboot in the middle go at the next update check, about ten minutes after the service starts.
