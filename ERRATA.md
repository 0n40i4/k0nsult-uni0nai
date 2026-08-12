# ERRATA — k0nsult-uni0nai

Corrections to claims this repository previously made in public. Recorded rather than
silently edited. Canonical index:
[`k0nsult-governance/ERRATA.md`](https://github.com/0n40i4/k0nsult-governance/blob/master/ERRATA.md).

## 2026-07-22 — "the guards no longer mask one another" was false

**Previous claim**, made in response to round 1 of an external audit: the negative test
vectors had been fixed so that guards in `validate()` no longer shadow each other.

**Status: FALSIFIED.** Round 2 re-tested it by mutation and we reproduced the result
independently. With the suite reporting **28/28 passed**, each of the following guards
could be disabled outright — its condition replaced with `if (false)` — **without a
single test failing**:

| guard | tests failing when disabled (before) |
|---|---|
| V1 role enum | 0 |
| V2 `subject_type` | 0 |
| V3 `public_key` | 0 |
| V4 private-key material | 0 |
| V5 person-PID field | 0 |
| V6 closed schema | 0 |

Cause: every legacy negative vector used a digit-less model slug (`did:k0nsult:claude:opus:judge`),
which fails the DID syntax check first. Each vector produced the expected `FAIL` verdict
for the wrong reason, so the guard it was written to exercise was never reached. A green
self-test was evidence of nothing.

Vectors have been rebased onto digit-bearing model slugs and isolating vectors added.
Every guard listed above now fails at least one test when disabled, and the baseline is
**30/30**. Reproduce by flipping any guard condition to `false` and re-running
`node did-resolver.mjs --selftest`.

Two further defects surfaced while fixing this: `validate()` **threw** instead of
returning a verdict when the DID-syntax branch was disabled (it is now total, always
returning a verdict), and a source comment asserted that `full_name` was absent from the
PII denylist when it is present in both `did-resolver.mjs` and `conformance.mjs`.

**Not fixed, stated instead:** one guard in `conformance.mjs` (rejecting an array-shaped
token) cannot be isolated by any vector — an array can never satisfy the preceding
`non_transferable === true` check, so that guard always fires second. It is redundant
defence in depth, and is now documented as such rather than counted as covered.

## 2026-07-22 — a live model fingerprint appeared in a public example

The canonical example in `schemas/did-agent.schema.json` named a real provider and the
then-current judge model. Elsewhere the repository uses synthetic placeholders. Replaced
with `did:k0nsult:acme:model-v2:judge`. This was disclosure hygiene, not a secret.

## 2026-07-22 — an in-progress review was cited as completed validation

`KNOWN-LIMITATIONS.md` cited the external adversarial review as though it had concluded.
It has not: round 2 produced further findings, and round 3 is expected. The reference now
reads as review in progress with findings open.
