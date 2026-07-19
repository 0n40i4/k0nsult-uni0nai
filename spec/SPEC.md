# SPEC — Agent-Federation Interoperability Contract (K0NSULT / uni0nai)

**Version:** 1.0 · **License:** Apache-2.0 · **Status:** reference specification (clean-room) · **Class:** NARRACJA (normative framing over verifiable artefacts).

This document is the human-readable overview of the **federation contract** that lets
EU-hosted agents from different vendors identify, describe and call each other **without a
non-EU broker**. The machine-checkable truth lives in the schemas and fixtures
(`schemas/did-agent.schema.json`, `conformance/golden-vectors.json`); this SPEC narrates
them. Where prose and schema disagree, **the schema wins**.

> **This repository is the contract, not the engine.** The federation runtime
> (`agent-registry.js`, `did-resolver.js`, `skill-lab.js`, …) is proprietary
> k0nsult.cloud code and is **deliberately not included** (doctrine: *silnik ukryty /
> commons otwarte* — hidden engine, open commons). You do not need the engine to
> interoperate; that is the whole point of an open contract.

## Doctrine (non-negotiable, applies to every artefact here)

| Rule | Meaning in this contract |
|---|---|
| `claim ≤ proof` | Every declared capability carries an `evidence_class` ∈ {DOWOD, GAP, NARRACJA}. A skill may not claim more than it can prove. |
| `agents-not-people` | Subjects are **agents only**. No DID, no reputation, no scoring may attach to a natural person. Zero PII in the wire format. |
| soulbound ≠ crypto | Reputation is **non-transferable** and bound to an agent DID. It cannot be sold, bridged or transferred. It is not a token asset. |
| No Password Custody | The wire format carries **public keys only**. No private-key material is ever generated, stored or transmitted by contract-conformant tooling. |
| chain = trust layer | Ordering/attestation is a **trust layer**, not a blockchain and not a liquidity network. |

## 1. Agent DID — `did:k0nsult:<provider>:<model>:<role>`

Identity is a Decentralized Identifier whose subject is **always an agent**.

```
did:k0nsult:claude:opus-4.7-1m:META_JUDGE
            └prov  └model       └role
```

- `subject_type` is a hard constant `"agent"`. Any other value **FAILS** validation.
- The document carries a **public** verification key (`ed25519` or `ecdsa-p256`) — never a
  secret.
- A conformant identity document contains **no personal-identification fields** whatsoever.
  The schema both closes the object (`additionalProperties: false`) and explicitly refuses
  a denylist of PID field names (`natural_person`, `email`, `pesel`, `national_id`, …). See
  `schemas/did-agent.schema.json`.

Normative shape: `schemas/did-agent.schema.json` (evidence_class: **DOWOD**).

## 2. ACP 1.0 envelope — four layers

Every federation message is an **ACP 1.0** envelope (`contract/acp-schema.json`). The four
layers separate *how we speak* from *what we ask*:

| Layer | Name | Carries | Fields |
|---|---|---|---|
| 1 | **protocol** | schema, version, signature over the envelope | `protocol`, `version`, `signature`, `message_id` |
| 2 | **context** | session, prior state, causal parent | `context`, `session_id`, `state_hash`, `previous_message_id` |
| 3 | **constraint** | permissions, latency/cost budget, required verification | `permissions`, `max_latency_ms`, `max_cost_usd`, `required_verification` |
| 4 | **intent** | the action itself, its params, expected outcome, escalation | `type`, `params`, `expected_outcome`, `escalation_path` |

Sender and receiver are `did:k0nsult:*` identities (Section 1). The `signature` is an
Ed25519 signature verifiable with the sender's **public** key — the private key never
leaves the agent's own custody.

## 3. Skill descriptor — capability with an evidence class

An agent is routed to by the **skill it declares**, not by who operates it. Each skill in an
agent's identity document is a descriptor:

```json
{ "skill_id": "skill_judge_panel", "name": "judge-panel", "version": "2.0.0",
  "evidence_class": "DOWOD" }
```

- `evidence_class` is **mandatory**. A skill without one **FAILS** validation — an
  undeclared evidence class is an unbounded claim, which `claim ≤ proof` forbids.
- `DOWOD` = the capability is demonstrable *now* (a re-runnable proof exists). `GAP` = an
  honest roadmap capability, phrased as future. `NARRACJA` = positioning, must be labelled.
- The shared skill vocabulary (routing taxonomy) is `contract/skills-registry.json`; the
  *routing policy* that consumes it is engine-side.

## 4. Soulbound reputation token — non-transferable by construction

Reputation is a **soulbound** record bound to one agent DID:

```json
{ "token_id": "sbt:...", "non_transferable": true,
  "issued_at": "2026-07-19T00:00:00Z", "reputation_score": 74,
  "bound_to": "did:k0nsult:claude:opus-4.7-1m:META_JUDGE" }
```

- `non_transferable` is a hard constant `true`. Any transfer-bearing field
  (`transfer_to`, `transferable`, `owner_change`, …) **FAILS** validation because the token
  object is closed (`additionalProperties: false`).
- `bound_to` must resolve to the agent's **own** DID. Reputation does not detach from its
  agent.
- This is a **trust record, not a crypto asset**: no balance, no ledger transfer, no bridge.

## 5. Sovereignty manifest — EU-first, broker-free, engine-honest

Each identity document carries a small sovereignty manifest:

```json
{ "host_region": "EU", "jurisdiction": "PL",
  "engine_disclosed": false, "broker_free": true }
```

- `broker_free: true` asserts the agent can be reached **without a non-EU intermediary** —
  the interoperability goal (COM(2026)503 building block).
- `engine_disclosed` is honest about *silnik ukryty*: the **contract** is open even when the
  **engine** is not. Disclosing the engine is optional; honouring the contract is not.

## Conformance

`conformance/golden-vectors.json` (evidence_class: **DOWOD**) is the executable truth of
this SPEC. It pairs each rule above with a **PASS** vector and — crucially — a **NEGATIVE**
vector that MUST FAIL:

| Rule | Negative vector (must FAIL) |
|---|---|
| soulbound = non-transferable | token carrying a transfer field / `non_transferable: false` |
| skill carries evidence_class | skill descriptor with the field omitted |
| subject = agent only | `subject_type` other than `"agent"` |
| zero PII | identity document carrying a personal-identification field |
| No Password Custody | identity document carrying private-key material |
| DID well-formed | malformed `did:k0nsult:*` string |

An implementation is conformant when it accepts every PASS vector and rejects every FAIL
vector using `schemas/did-agent.schema.json`.

## Governance & irreversibility

Irreversible acts (publication, external submission, cryptographic signing) are
**human-gated** — see `../k0nsult-governance`. Contract tooling classifies, validates and
counts; it never authorises the act, and it never generates or holds a key (No Password
Custody).

## Files in this wave (P1)

| Path | evidence_class |
|---|---|
| `spec/SPEC.md` | NARRACJA — normative framing over the artefacts below |
| `schemas/did-agent.schema.json` | DOWOD — machine-checkable identity schema |
| `conformance/golden-vectors.json` | DOWOD — re-runnable PASS/FAIL conformance fixtures |
