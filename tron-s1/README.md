# TRON S-1 — same-block permission revocation bypass (reproduction)

**Shape.** On java-tron's block-*validation* path (`Manager.pushBlock ->
processBlock`), a block containing, in order,

1. **R** — an `AccountPermissionUpdateContract` that revokes key K of account V, then
2. **S** — a transaction from V signed by K,

is **accepted and S executes**, even though R has already been applied earlier
in the same block. Signature verification is memoized per transaction capsule
and the block's batch verification runs against pre-block state; the
sequential apply loop never re-verifies S after R lands. The same `[R, S]`
pair split across two blocks is rejected. Sibling paths are defended
(generation: `generateBlock` reset; fork-switch: `switchFork` flush;
re-push: PR #6716; cross-block pool trust: PR #6796) — the same-block
validation path is the one place the team's own remediation pattern is
missing.

Pinned target: `tronprotocol/java-tron` @
`b33eed89a6a424c498d4fb1b03ca2c86eddf4840` (master, 2026-09-11).

## Contents

- `ManagerSameBlockRevocationTest.java` — JUnit test (extends
  `BaseMethodTest`, lives in `org.tron.core.db`) with three cases:
  - `sameBlockRevocationDoesNotInvalidateLaterSpend` — the bug case through
    `pushBlock`. **Passes only at vulnerable HEAD**; a correct fix makes
    `pushBlock` throw `ValidateSignatureException` and this test fail.
  - `crossBlockRevocationInvalidatesSpend` — control A: `[R]`, then `[S]`
    in the next block → rejected.
  - `crossBlockPooledSpendRejectedAfter6796` — control B: PR #6796's own
    regression scenario (pooled pre-verified spend, `ownerAddressSet` still
    carrying the owner) driven through the full `processBlock` path →
    rejected.
- `.github/workflows/tron-s1.yml` (repo root) — GitHub Actions workflow:
  checks out java-tron at the pinned commit, installs the test into
  `framework/src/test/java/org/tron/core/db/`, runs
  `./gradlew :framework:test --tests "org.tron.core.db.ManagerSameBlockRevocationTest"`,
  and publishes the JUnit XML + marker lines to the run's step summary.

Full analysis: `~/workspace/bugbounty/tron-hunt-2.md` (S-1) and
`~/workspace/bugbounty/tron-s1-repro.md` (execution record).
