# EU Crosswalk — `did:k0nsult` ↔ eIDAS2 / EUDI / EUID

**Version:** 1.0 · **License:** Apache-2.0 · **Status:** reference specification (clean-room) · **Class:** NARRACJA (positioning against external EU standards; the verifiable artefacts remain the schema + golden vectors).

This crosswalk positions the **agent-identity contract** (`did:k0nsult`, `spec/DID-METHOD-SPEC.md`) against the EU identity stack — **eIDAS2** (Regulation (EU) 2024/1183), the **EUDI Wallet**, and the **EUID** European Unique Identifier for company/business registers (interconnection under Directive (EU) 2017/1132 / the BRIS). It is a **map, not a merge**: it shows what MAPS, what we EXTEND, and what is deliberately OUT-OF-STANDARD, and it draws one hard, load-bearing line.

> **The hard line (non-negotiable).** eIDAS2/EUDI and EUID identify **persons** — a
> **natural person** (EUDI Wallet PID) or a **legal person / registered entity** (EUID,
> legal-person attestations). `did:k0nsult` identifies an **AGENT** and only an agent
> (`agents-not-people`). These are **different subject classes** and MUST NOT be collapsed.
> **PID never travels on-wire** in an agent document or an ACP envelope. A person may
> *approve, own or be accountable for* an agent **off-wire, through their own wallet**; that
> approval is never embedded as PID in the contract artefacts.

## Why a crosswalk and not a profile

eIDAS2 has **no subject class for a software agent**. Its trust anchors are people and legal entities. Forcing an agent into a person/legal-person slot would either (a) attach a person's PID to a piece of software — a privacy and `agents-not-people` violation — or (b) misuse a legal-person identity as if it were the actor, hiding which agent actually acted. The crosswalk keeps the two worlds **interoperable but distinct**: an agent is accountable *to* a person/entity in the EU stack, without *becoming* one on the wire.

## Subject-class table (the thing that must never blur)

| Subject class | EU standard | Identifier | May it appear on-wire in this contract? |
|---|---|---|---|
| Natural person | eIDAS2 / EUDI Wallet | PID (given name, family name, DoB, national id…) | **NO. Never.** PID is forbidden by the schema anti-PID guard. |
| Legal person / registered entity | EUID (BRIS), eIDAS legal-person attestation | EUID (country + register + entity number), LEI (optional) | **Only as an off-wire accountability anchor** referenced by governance, **not** as a field in the agent document or ACP envelope. |
| **Software agent** | **`did:k0nsult`** (this contract) | `did:k0nsult:<provider>:<model>:<role>` | **YES — this is the only subject the wire format carries.** |

## Crosswalk — MAPS · EXTENDS · OUT-OF-STANDARD

| Concept | eIDAS2 / EUDI / EUID | `did:k0nsult` | Relation |
|---|---|---|---|
| Identifier of the acting subject | EUDI PID (person) / EUID (legal person) | `did:k0nsult` DID (agent) | **OUT-OF-STANDARD** — new subject class (agent). eIDAS2 has none; we do not overload theirs. |
| Cryptographic proof of control | QES / QSCD, wallet-held keys | Ed25519 (PQC-ready ML-DSA) public key, operator custody | **MAPS** — both are public-key proof of control. We map the *shape*; we do not use a QSCD and make **no QES claim** (GAP if ever pursued). |
| Key custody | Wallet / QSCD holds the person's key | **No Password Custody** — operator holds the key, contract tooling holds none | **EXTENDS** — stricter than required: contract tooling never generates or stores a secret. |
| Selective disclosure of attributes | EUDI selective disclosure / ZKP of PID attributes | Skill descriptors with `evidence_class`; sovereignty manifest | **EXTENDS in a different plane** — we disclose **agent capabilities**, not person attributes. No PID to selectively disclose because there is none. |
| Trust list / accreditation | eIDAS Trusted Lists (QTSPs) | Federation registry role (`registry`) + trust-layer log | **MAPS (conceptually)** — a discoverable set of trusted participants. Our registry lists **agents**, not QTSPs, and issues no qualified status. |
| Legal-entity anchoring | EUID via BRIS interconnection | Governance-side operator accountability (off-wire) | **OUT-OF-STANDARD on-wire / MAPS off-wire** — the responsible legal entity is anchored by **governance**, never by an EUID field inside the agent document. |
| Cross-border reachability | eIDAS interoperability / notified schemes | `sovereignty_manifest.broker_free = true` | **MAPS** — both target broker-free cross-border interoperability (COM(2026)503 building block). |
| Reputation / standing | (not in scope of eIDAS2) | soulbound, non-transferable, bound to agent DID | **OUT-OF-STANDARD** — eIDAS2 does not model agent reputation; ours is soulbound, not a credential a person carries. |
| Post-quantum readiness | PQC migration under EU cybersecurity roadmap | `public_key.type` extensible to ML-DSA / hybrid | **MAPS (direction)** — same migration intent; declared **GAP** until schema-versioned. |

## The person↔agent relationship (how they touch without merging)

A person or legal entity relates to a `did:k0nsult` agent **off-wire**, in three permitted ways — none of which put PID on the wire:

1. **Approval / authorisation.** A person may use their **EUDI Wallet** to sign an *authorisation event* that a governance system records (e.g. "operator X authorises agent `did:k0nsult:…` to act within scope Y"). The **wallet PID stays in the wallet**; what the agent document/ACP envelope carries is, at most, an opaque authorisation reference — never the PID itself.
2. **Accountability.** The responsible **legal entity** (identified by **EUID** in a business register, off-wire) is recorded by governance as accountable for the agent. The agent document does not embed the EUID.
3. **Consent for actions with legal effect.** Where an agent action needs a person's qualified consent, that consent is produced by the person's wallet **out of band** and referenced, not inlined.

> Consequence: resolving an agent DID **cannot** reveal a person. De-anonymising the human
> behind an agent requires a **separate, governance-gated** step against wallet/register
> systems that this contract neither performs nor stores. That separation is the privacy
> guarantee.

## Anti-patterns (MUST NOT)

- ❌ Embedding EUDI PID (name, DoB, national id) anywhere in an agent document or ACP envelope. *(Blocked by the schema anti-PID `not` guard.)*
- ❌ Using an EUID/LEI **as** the agent identifier, or as an on-wire field, to make a legal person masquerade as the acting agent.
- ❌ Claiming **QES / qualified trust status** for a `did:k0nsult` signature. We map the cryptographic shape; we assert no qualified status (that would be NARRACJA dressed as DOWOD).
- ❌ Treating an agent DID as a person's eID, or a person's eID as an agent DID.

## Conformance notes

This crosswalk is **advisory positioning** (NARRACJA). Its one *enforced* invariant is already machine-checked elsewhere: **no PID on-wire** is guaranteed by `schemas/did-agent.schema.json` (`additionalProperties:false` + anti-PID `not` guard) and exercised by the negative PII vector in `conformance/golden-vectors.json` (**DOWOD**). Any future EUDI/EUID *reference field* (e.g. an opaque authorisation-reference) is a **versioned schema change** with its own golden vectors — never an ad-hoc field.

## Standards referenced (as references, not forked)

- Regulation (EU) 2024/1183 (**eIDAS2**) and the **EUDI Wallet** framework.
- **EUID** — European Unique Identifier, business-register interconnection (BRIS), Directive (EU) 2017/1132.
- COM(2026)503 — EU agent-interoperability building block (broker-free cross-border reachability).

| Path | evidence_class |
|---|---|
| `spec/EU-CROSSWALK.md` (this file) | NARRACJA — positioning against eIDAS2/EUDI/EUID |
| `schemas/did-agent.schema.json` | DOWOD — enforces *no PID on-wire* |
| `conformance/golden-vectors.json` | DOWOD — negative PII vector proves the hard line |
