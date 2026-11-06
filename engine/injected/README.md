# Injected script sources

What the engine puts into pages next to the scriptlets (plan 5.5, 5.6).

| File | What | Licence |
|---|---|---|
| `procedural_filters.ts` | Brave's procedural filter applier, the pin below plus the patches below and nothing else. It selects elements and does nothing else. | MPL-2.0 (its header is kept) |
| `procedural-applier.js` | That file transpiled by `pnpm injected:build`, checked in so cargo builds do not need node. | MPL-2.0 (same file, same header) |
| `bootstrap.js` | Sieve's runner: the actions (hide, remove, style, remove-attr, remove-class), first run, MutationObserver. | GPL-3.0-only, as the rest of Sieve |

## The pin

- Source: https://github.com/brave/brave-core/blob/a46f4e864ae33b38e02bee1d72f95364d4677290/components/cosmetic_filters/resources/data/procedural_filters.ts
- Commit: `a46f4e864ae33b38e02bee1d72f95364d4677290` (2026-08-17)
- Size: 20557 bytes
- SHA-256 of that file: `85a6545f0138127eb86bd5a9ac1d5c852c3c74f34b75d9414c153b199de97c6b`

## The patches

Two defects of the pinned file, carried until Brave fixes them (neither has been reported to Brave yet):

1. `_compileRegEx` splits on every `/`, so `/foo\/bar/` compiles a pattern of `foo\` with flags `bar`, which throws and leaves the filter inert. It now takes the last `/` as the end of the pattern.
2. `_allOtherSiblings`, the `~` combinator, returns the siblings before the element too, where CSS has only those after it, so a `:remove()` could delete unrelated content. It now returns the ones after it.

`tests/laws/injected.test.ts` undoes exactly these edits and checks the result against the pin's hash, checks that a rebuild equals the checked-in `.js`, and the header in both. `.gitattributes` keeps these bytes through a CRLF checkout.

To bump: replace the `.ts` with the new commit's file, reapply what is still needed, update the pin here and the pin and the patches in the law, run `pnpm injected:build`, and read the diff: this code runs in every page.
