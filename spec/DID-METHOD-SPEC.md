# DID Method Specification — `did:k0nsult`

**Version:** 1.0 · **License:** Apache-2.0 · **Status:** reference specification (clean-room) · **Class:** NARRACJA (normative framing over the DOWOD artefact `schemas/did-agent.schema.json`).

This document specifies the **`did:k0nsult` DID method** in the shape of [W3C DID Core 1.0](https://www.w3.org/TR/did-core/): identifier syntax, the DID document, verification material, resolution, and the CRUD operations. It is the *method* layer beneath `spec/SPEC.md`, which narrates how the identity is *used* in the federation. The machine-checkable identity shape is `schemas/did-agent.schema.json` (evidence_class **DOWOD**); this method spec does **not** restate it — where prose and schema disagree, **the schema wins**.

> **Contract, not engine.** The resolver, registry and key-rotation runtime are
> a private engine (proprietary k0nsult.cloud code) and are **deliberately not
> included**; its internal module layout is not disclosed (doctrine: *silnik ukryty / commons otwarte*). This
> spec defines what any conformant, independently-built resolver MUST do.

## Doctrine binding (non-negotiable)

| Rule | Effect on this method |
|---|---|
| `agents-not-people` | The DID subject is **always an agent**. No `did:k0nsult` identifier may denote or embed a natural person. `subject_type` is the hard constant `"agent"`. |
| No Password Custody | The DID document carries **public verification keys only**. Conformant tooling never generates, stores or transmits a private key. Create / rotate / deactivate are all authorised by a **signature the operator produces**, never by the agent minting its own secret. |
| soulbound ≠ crypto | Reputation bound to a DID (see SPEC §4) is non-transferable; the DID is an identity anchor, **not** a wallet or an on-chain address. |
| `claim ≤ proof` | Every skill referenced from the DID document carries an `evidence_class`. A DID advertises capability only up to what it can prove. |
| chain = trust layer | Ordering/attestation of DID events is a **trust layer** (append-only log), not a blockchain and not a ledger of assets. |

## 1. Method name

The method name is the ASCII string **`k0nsult`**. A DID that uses this method MUST begin with the prefix `did:k0nsult:` (case-sensitive).

## 2. Method-specific identifier

```
did:k0nsult:<provider>:<model>:<role>
            └prov      └model    └role
```

ABNF (aligned with the schema pattern `^did:k0nsult:[A-Za-z0-9-]+:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$`):

```abnf
k0nsult-did   = "did:k0nsult:" provider ":" model ":" role
provider      = 1*( ALPHA / DIGIT / "-" )
model         = 1*( ALPHA / DIGIT / "." / "_" / "-" )
role          = 1*( ALPHA / DIGIT / "." / "_" / "-" )
```

- `provider` — the vendor/host of the agent runtime (e.g. `claude`, `mistral`, `local`). It is an **operator-of-an-agent** label, never a person.
- `model` — the model family/version the agent runs (e.g. `opus-v2`).
- `role` — the federation role, drawn from the schema `role` enum: `executor` | `orchestrator` | `judge` | `observer` | `registry`.

Example: `did:k0nsult:claude:opus-v2:judge`.

The identifier MUST NOT encode any personal identifier (name, email, PESEL/national id, wallet PID). Anti-PID enforcement lives in the schema `not` guard and is normative.

## 3. DID document

A `did:k0nsult` DID **resolves to** an *agent identity document* whose normative shape is `schemas/did-agent.schema.json`. In DID-Core terms the mapping is:

| DID-Core concept | `did:k0nsult` realisation |
|---|---|
| `id` | the `did` field (`did:k0nsult:<provider>:<model>:<role>`). |
| `verificationMethod` | the `public_key` object: `{ "type": "ed25519" \| "ecdsa-p256", "value": <public key> }`. Public key material **only**. |
| `authentication` / `assertionMethod` | the same `public_key`; it verifies ACP envelope signatures (SPEC §2) and soulbound attestations (SPEC §4). |
| `service` | reachability is asserted by `sovereignty_manifest` (`host_region`, `broker_free`); concrete endpoints are engine-side and out of contract. |
| controller | **the human operator**, off-document. No Password Custody: the controller holds the signing key; the document never does. |

The document additionally carries `soulbound_token`, `skills[]` (each with `evidence_class`) and `sovereignty_manifest`, per the schema. A conformant document is **closed** (`additionalProperties:false`) and carries **zero** PID and **zero** private-key fields.

## 4. Verification material — Ed25519 now, PQC-ready

- **Current (MUST):** `ed25519` public verification key. `ecdsa-p256` is an accepted alternative for interop with eIDAS-adjacent tooling.
- **PQC-ready (SHOULD, forward path):** the `public_key.type` vocabulary is designed to extend to a NIST post-quantum signature — **ML-DSA** (FIPS 204, Dilithium) — and to **hybrid** classical+PQC material, so that identity survives the migration window the AI Act / cybersecurity roadmap anticipates. Until the schema enum is extended by a versioned change, PQC keys are declared as **GAP** (honest roadmap), never asserted as **DOWOD**. Adding a PQC type is a **contract change** (new schema version + new golden vectors), not an out-of-band field.
- A document MUST NOT carry more than one *active* key of a given purpose except during a **rotation overlap** (§6.2).

> Rationale for PQC-ready: an agent identity is long-lived trust anchor material; a
> harvest-now-decrypt-later adversary targets exactly such anchors. The method commits to a
> migration path **by construction** rather than a rewrite.

## 5. Resolution

Resolving `did:k0nsult:<provider>:<model>:<role>` returns the agent identity document (§3) plus DID-Core **resolution metadata**.

A conformant resolver MUST:

1. Reject any identifier that fails the schema `did` pattern → resolution error `invalidDid`.
2. Return a document that **validates against `schemas/did-agent.schema.json`**, or fail with `notFound` / `documentInvalid`. A resolver MUST NOT return a document that carries PID or private-key material even if such a document was somehow stored — anti-PID is a resolution-time invariant, not only a storage-time one.
3. Report `deactivated: true` for a deactivated DID (§7) and MUST NOT resolve it as active.
4. Never return, log or cache private-key material (there is none to return).

Resolver *mechanism* (transport, registry backend, caching) is engine-side and out of contract. Two independently built resolvers are interoperable iff they agree on §2 syntax and §3 document validity.

## 6. CRUD without custody

All state-changing operations are authorised by a signature the **operator** produces with a key the **operator** holds. The agent and any contract-conformant tool **never generate or store** a private key (No Password Custody). Tooling MAY assemble the document/event to be signed and MAY verify the resulting signature with the **public** key; it MUST NOT create the secret.

### 6.1 Create

- The operator provisions a keypair **outside** contract tooling (their own HSM/wallet/`ssh-keygen`-class custody).
- The initial agent identity document is assembled with the **public** key in `public_key` and MUST validate against the schema before it is considered created.
- Publication of the document is an **irreversible act** and is **human-gated** (see `../k0nsult-governance`). Tooling classifies and validates; it does not authorise publication.

### 6.2 Update = key rotation (custody-free)

Rotation replaces the active verification key **without any secret leaving the operator**:

1. Operator generates the **new** keypair in their own custody.
2. A **rotation event** binds `{ did, previous_public_key, new_public_key, rotated_at }` and is **signed by the *previous* (still-valid) private key** — proving continuity of control — by the operator, off-tool.
3. The updated document carries the **new** public key; a short **overlap** window MAY list both keys so in-flight ACP messages verifying against the old key still validate.
4. The rotation event is appended to the DID's **trust-layer log** (append-only, ordering only — not a blockchain, not a token transfer).

At no point is a private key handled by contract tooling. A rotation whose event is not signed by the prior key is **not** a valid rotation and MUST be rejected.

### 6.3 Read

See §5 (resolution).

## 7. Deactivate (Delete)

Deactivation is **append-only**, honouring *archiwizuj, nie usuwaj*:

- A **deactivation event** `{ did, deactivated_at }` is signed by the **current** private key (operator-held) and appended to the trust-layer log.
- The resolver thereafter reports `deactivated: true`; the DID is never re-activated and its identifier is never reissued to a different agent.
- The historical document and its rotation/deactivation events are **retained** (audit), not erased. Because the document carries no PID, retention raises no personal-data-erasure obligation.

## 8. Security & privacy considerations

- **No custody:** the strongest key-compromise limiter is that conformant tooling holds no secret to compromise. Key loss/theft is contained to the operator's own custody boundary and remediated by rotation (§6.2).
- **Anti-PID (best-effort, NOT a guarantee):** by `agents-not-people`, a DID document is not meant to carry personal data. The guard is a **denylist of person-identifying field names** (multilingual, but not exhaustive) plus a value-scan for ID-shaped strings (national-id/email/phone). This **raises the cost** of smuggling PID; it does **not** prove a document is free of personal data — a dossier using field names outside the denylist, in free-text values, passes. The closed-schema guard is **top-level only**. Do not read this as "resolution cannot leak a person"; read it as "obvious PID is rejected, the rest is the deployer's responsibility." See `KNOWN-LIMITATIONS.md`.
- **PQC migration:** treated as a first-class, versioned evolution (§4), declared GAP until proven DOWOD.
- **Irreversibility:** create/rotate/deactivate publish to a shared trust layer and are **human-gated**; agents never self-authorise an irreversible identity act.

## 9. Conformance

A `did:k0nsult` implementation is conformant when it:

1. Accepts only identifiers matching §2 / the schema `did` pattern.
2. Resolves to documents that validate against `schemas/did-agent.schema.json` (and rejects PID / private-key-bearing documents).
3. Performs Create/Update/Deactivate such that **no private key is generated or held by the tooling** and every state change is authorised by an operator signature (rotation by the *prior* key).
4. Treats PQC key types as a **versioned schema change**, declared GAP until the enum and golden vectors are updated.

The PASS/FAIL vectors for the identity document itself live in `conformance/golden-vectors.json` (evidence_class **DOWOD**).

## Files referenced

| Path | evidence_class |
|---|---|
| `spec/DID-METHOD-SPEC.md` (this file) | NARRACJA — method framing over the schema |
| `schemas/did-agent.schema.json` | DOWOD — normative identity document shape |
| `conformance/golden-vectors.json` | DOWOD — PASS/FAIL fixtures |
