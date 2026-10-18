# Second review of ee9a45e and its fixes (Opus, standing in for Codex)

Codex hit its usage limit on 2026-10-18 (it resets 2026-10-25), so per the machine rules an Opus subagent did the second review, read-only.

## ee9a45e: relay experiments merge. Verdict: MERGE-SAFE

- With the feature off, every `relay-experiments` arm is compiled out. Route deletion stays fail-open. The only production change is reporting: a replay with real failures now says FAILED, which sets `last_error` at start-up and makes the uninstall and restore verbs exit non-zero. The NSIS hook ignores that exit code.
- Findings, all fixed:
  1. **A production bug that predates this merge**, fixed in f171c44. `relay_tcp` lost the tail of a deciding read that overflowed the classifier's cap: 1,436 bytes in the regression test, which fails without the fix.
  2. The experimental relay held about 3x `copy_buffer_bytes` per flow. Fixed in 1deb54c with a shared `CLASSIFIER_READ` buffer, dropped before the copy phase.
  3. The batch queue holds far fewer packets under sparse traffic. Documented in `tun/batch.rs` in 1deb54c.
  4. A BOM-prefixed `experiments.json` was refused. Fixed in 1deb54c: a UTF-8 BOM is stripped and UTF-16 is refused by name.
  5. A duplicated 16 KiB constant. Fixed in 1deb54c with `CLASSIFIER_READ`.
  6. `experiments.json` was read without a size limit. Fixed in 1deb54c: the read is capped at 4 KiB.
- Separately, before the review, 85e63cb restored `ERROR_FILE_NOT_FOUND` as "already gone". The merged classifier had turned it into a failure.

## f171c44 and 1deb54c. Verdict: MERGE-SAFE

The spill arithmetic is right in every case: a read that fit, a read that overflowed, a timeout, the cap decision, and a push that kept nothing. Nothing is duplicated or reordered, `bytes_up` is right, and the drop path still sends nothing. The new test makes its decision on an overflowing read, and the HTTP head completes at 1,487 bytes. Production is unaffected by 1deb54c.
