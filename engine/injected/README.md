# Injected script sources

What the engine puts into pages next to the scriptlets (plan 5.5, 5.6).

| File | What | Licence |
|---|---|---|
| `procedural_filters.ts` | Brave's procedural filter applier, byte-identical to the pin below. It selects elements and does nothing else. | MPL-2.0 (its header is kept) |
| `procedural-applier.js` | That file transpiled by `pnpm injected:build`, checked in so cargo builds do not need node. | MPL-2.0 (same file, same header) |
| `bootstrap.js` | Sieve's runner: the actions (hide, remove, style, remove-attr, remove-class), first run, MutationObserver. | GPL-3.0-only, as the rest of Sieve |

## The pin

- Source: https://github.com/brave/brave-core/blob/a46f4e864ae33b38e02bee1d72f95364d4677290/components/cosmetic_filters/resources/data/procedural_filters.ts
- Commit: `a46f4e864ae33b38e02bee1d72f95364d4677290` (2026-08-17)
- Size: 20557 bytes
- SHA-256: `85a6545f0138127eb86bd5a9ac1d5c852c3c74f34b75d9414c153b199de97c6b`

`tests/laws/injected.test.ts` checks the hash, that a rebuild equals the checked-in `.js`, and the header in both. `.gitattributes` keeps these bytes through a CRLF checkout.

To bump: replace the `.ts` with the new commit's file, update the pin here and in the law, run `pnpm injected:build`, and read the diff: this code runs in every page.
