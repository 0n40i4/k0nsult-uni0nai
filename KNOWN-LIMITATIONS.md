# KNOWN LIMITATIONS — read before relying on these tools

**Status: REFERENCE / EXPERIMENTAL.** The validators in the K0NSULT open commons
(`conformance.mjs`, `did-resolver.mjs`, and the sibling tools in `k0nsult-tools` /
`k0nsult-eu-shield`) are **reference implementations of a specification**, not
production-grade security or privacy guards. **Do not rely on them as your sole
PII / private-key / accessibility enforcement layer.**

This file is published deliberately. The commons has undergone **four rounds of
internal adversarial review** (5-judge and 20-specialist panels, each prompted to
*refute*; commissioned by the maintainer, not third parties). A separate
**external review (roxkon / RSpace) is IN PROGRESS — round 2 of an unfinished
series; its findings are open, not closed, and it must not be read as a completed
third-party validation or sign-off.** Every finding — including the ones still open
below — is public. That
transparency is the point: `claim ≤ proof` means we document exactly where the tools
are incomplete rather than overclaiming they are bulletproof.

## Known open weaknesses (from the adversarial audit)

These are **structural limitations of regex/denylist-based validation**, not one-off
bugs. Closing each class tends to reveal the next; we state them plainly instead.

### PII / private-key detection (conformance.mjs, did-resolver.mjs, art50, dep-provenance)
- **Scalar array elements may not be scanned.** PII/PEM placed as a *string element of
  an array* (e.g. `skills[].contacts[]`) can pass. The scan covers object values, not
  every array scalar.
- **Regexes are ASCII-centric.** `\d` does not match full-width/Arabic-Indic digits, so a
  PESEL written `４４…` or split with spaces/zero-width chars can pass. `EMAIL_RE` requires
  a dotted TLD, so `admin@localhost` or IDN/internal addresses can pass.
- **Key-name denylist is not camelCase-normalised in every path.** `passportNumber`,
  `dateOfBirth`, `homeAddress` (camelCase) may pass where the snake_case form fails.
- **11-digit PESEL as a JSON number** (not string) bypasses the string value scan.
- **PGP block vs PEM.** The private-key value scan matches `-----BEGIN … PRIVATE KEY-----`
  but not `-----BEGIN PGP PRIVATE KEY BLOCK-----` in every tool.
- **Validator drift.** `conformance.validate()` and `did-resolver.validate()` do not enforce
  an identical rule set — a document may PASS one and FAIL the other. Treat them as two
  independent partial checks, not one canonical gate.
- **Closed schema is top-level only.** Sub-trees (`public_key`, `skills`, `token`) are guarded
  by denylist, not a recursive allowlist.

**Consequence:** these tools reduce, but do **not eliminate**, the risk of PII or key
material entering an artefact. For real enforcement, pair them with a reviewed,
allowlist-based, Unicode-normalising, structure-aware validator and human review.

### Soulbound / transfer (conformance.mjs R4)
- Transfer-shape detection is a **name denylist**; novel aliases (`new_owner`, `recipient`,
  `beneficiary`, `airdrop`, `escrow`, …) may certify a transferable token as "soulbound".

### Test coverage
- **Self-tests assert the verdict, not the rule** — this was measured, not assumed. External
  review round 2 (roxkon / RSpace) found, and we reproduced by mutation testing, that **all
  six `did-resolver.validate()` guards could be replaced with `if (false)` while the
  self-test stayed 28/28 green**: every legacy negative vector used a digitless model slug
  (`did:k0nsult:claude:opus:judge`), so the id-syntax guard fired first and masked the guard
  the vector was supposed to exercise — right verdict, wrong reason.
- **Current state (mutation-verified, reproducible).** Negative vectors were rebased onto
  digit-bearing model slugs and isolating vectors added. Disabling any single guard now
  breaks at least one vector: `did-resolver.mjs` 9/9 guards isolated (30/30 baseline),
  `conformance.mjs` 11/12 (28/28 baseline). Reproduce by flipping one guard condition to
  `false` and re-running `--selftest`.
- **Still not isolatable (stated openly):** `conformance.mjs` R4 "token must not be an array"
  is redundant — an array token can never expose `non_transferable:true`, so the
  `non_transferable` guard already fails it. Disabling the array branch alone breaks no
  vector; do not read it as an independently proven guard.
- A green self-test still proves only what its vectors cover. Mutation coverage of the other
  commons repos (`k0nsult-tools`, `k0nsult-eu-shield`) is roadmap.

## What IS solid (also from the audit)
- No repo generates, stores, or requests a private key (No Password Custody holds).
- `attest-verify` never signs (`SIGNER=none ⇒ UNSIGNED_DRAFT`, `keyless ⇒ HALT_FOR_ACK`).
- No leaked secrets/keys in the working tree or git history; Apache-2.0 `LICENSE` byte-identical.
- Path-traversal, dead-hash, ReDoS length-cap and recursion-depth guards are in place.

## How to help
Run the tools, try to break them, and open an issue or PR with a reproducing input.
That is exactly how the findings above were surfaced.
