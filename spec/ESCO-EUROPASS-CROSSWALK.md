# ESCO / Europass Crosswalk — agent skills as **competence**, referenced not forked

**Version:** 1.0 · **License:** Apache-2.0 · **Status:** reference specification (clean-room) · **Class:** NARRACJA (a shared-vocabulary mapping; the verifiable capability truth stays with each skill's `evidence_class`).

This crosswalk lets a `did:k0nsult` agent describe **what it can do** using the EU's established competence vocabularies — **ESCO v1.2** (European Skills, Competences, Qualifications and Occupations), **Europass EDCI / EDC** (European Digital Credentials for Learning), and the **EQF** (European Qualifications Framework, 8 levels) — as a **reference**, never a fork.

> **Two hard lines (non-negotiable).**
> 1. **Competence attaches to the AGENT, not a person** (`agents-not-people`). An ESCO skill
>    URI on an agent descriptor describes the **agent's** capability. It is **never** a
>    person's CV, qualification, or credential. No natural person is scored, listed or
>    identified.
> 2. **Reference, not fork, and never a proof-substitute.** Citing an ESCO/EQF URI is a
>    **shared label** (NARRACJA / vocabulary). It does **not** raise a skill's evidence
>    class. A skill is `DOWOD` only when a **re-runnable proof** exists — an ESCO tag never
>    makes a `GAP` into a `DOWOD`.

## What we borrow, and what we refuse to borrow

ESCO and Europass were built to describe **human** skills, occupations and qualifications for the labour market. We reuse their **taxonomy of competence** (a stable, multilingual, URI-addressable vocabulary) so that two vendors' agents can say "I can do *the same thing*" in a language a European buyer already understands. We refuse everything about them that assumes a **person**: no occupation-as-job-for-a-human, no learner record, no qualification awarded to an individual, no PID.

## Crosswalk — MAPS · EXTENDS · OUT-OF-STANDARD

| Concept | ESCO v1.2 / Europass / EQF | `did:k0nsult` skill descriptor | Relation |
|---|---|---|---|
| A named capability | ESCO **skill/competence** concept (URI, multilingual label) | `skills[].name` + optional `esco_ref` (ESCO URI) | **MAPS** — an agent skill MAY cite the ESCO skill URI it realises. Reference only. |
| Capability grouping | ESCO **skills pillar** hierarchy | `contract/skills-registry.json` routing taxonomy | **EXTENDS in a different plane** — our taxonomy is a **routing** vocabulary for agents; it aligns *to* ESCO groups but is not a re-issue of ESCO. |
| Occupation | ESCO **occupation** (a job a person holds) | *(none)* | **OUT-OF-STANDARD / refused** — an agent has **no occupation**. Occupations presuppose a human worker; mapping one to an agent would smuggle person-modelling in. |
| Proficiency level | EQF **level 1–8** (of a person's qualification) | optional `eqf_level_ref` as a **coarse capability band**, decoupled from any qualification | **EXTENDS** — reused only as a *comparability scale for the agent's capability*, never as a qualification a person earned. |
| Credential of achievement | Europass **EDC / EDCI** verifiable credential issued **to a learner** | soulbound reputation bound to the **agent** DID (SPEC §4) | **OUT-OF-STANDARD** — EDC credentials are issued to **people**; our standing is **soulbound to an agent**, non-transferable, not a personal credential. |
| Evidence of the claim | (Europass leans on the issuer's authority) | `evidence_class` ∈ {DOWOD, GAP, NARRACJA} per skill | **EXTENDS** — every capability is **self-classified for proof**. An ESCO tag is *vocabulary*; the *proof* is the evidence_class + a re-runnable artefact. |
| Multilinguality | ESCO 28-language labels | inherited by reference (we cite the URI, ESCO supplies the labels) | **MAPS** — we get multilingual capability labels **for free** by referencing, not copying. |

## How a skill cites ESCO/EQF (reference shape)

An agent skill descriptor (normative shape in `schemas/did-agent.schema.json`) MAY be **annotated** with reference URIs. In the current schema version these live as an **extension convention** (declared **GAP** until the schema enum/fields are versioned to accept them — adding them is a contract change, not an ad-hoc field):

```json
{
  "skill_id": "skill_judge_panel",
  "name": "judge-panel",
  "version": "2.0.0",
  "evidence_class": "DOWOD",
  "esco_ref": "http://data.europa.eu/esco/skill/<uuid>",
  "eqf_level_ref": 6
}
```

Rules for the reference fields:

- `esco_ref` MUST be a resolvable **ESCO concept URI** (`data.europa.eu/esco/skill/…`). It is a **pointer into ESCO**, not a local copy of ESCO data — *reference, not fork*.
- `eqf_level_ref` (if used) is a **coarse capability band 1–8**, explicitly **not** a qualification, diploma or level *awarded to a person*.
- Neither field may carry a person, a learner id, an issuer-of-a-personal-credential, or any PID. The schema anti-PID guard remains in force.
- Neither field changes `evidence_class`. If the demonstrable proof is absent, the skill is `GAP` **even if** it carries a perfectly valid ESCO URI.

## Anti-patterns (MUST NOT)

- ❌ Presenting an agent's ESCO-tagged skills as a **person's** competences, CV or Europass profile.
- ❌ Issuing or embedding a **Europass EDC credential to a natural person** through this contract. Personal credentials are out of scope and out of doctrine.
- ❌ Mapping an agent to an ESCO **occupation** (that models a human job).
- ❌ Treating an ESCO/EQF reference as **evidence**. A URI is a label; DOWOD needs a re-runnable proof.
- ❌ **Forking** ESCO/Europass data into the repo. We reference the canonical `data.europa.eu` URIs; we do not vendor a copy that could drift and mislead.

## Why reference-not-fork matters here

ESCO v1.2 is maintained, versioned and multilingual by the Commission. Forking it would (a) freeze a snapshot that silently goes stale, (b) create a second source of truth that contradicts the canonical one, and (c) tempt a slide from *agent capability vocabulary* back toward *human occupation data*. Referencing keeps a **single canonical source**, inherits its multilinguality, and keeps our repo firmly a **contract about agents**.

## Conformance notes

This crosswalk is advisory (NARRACJA). The invariants it depends on are enforced by the DOWOD artefacts: every skill **must** carry an `evidence_class` (schema-required — a skill without one FAILS, per the negative vector in `conformance/golden-vectors.json`), and **no PID** may ride along (anti-PID `not` guard). ESCO/EQF reference fields are a **versioned schema extension** (GAP today); adding them ships with their own golden vectors.

## Standards referenced (as references, not forked)

- **ESCO v1.2** — European Skills, Competences, Qualifications and Occupations (`data.europa.eu/esco`).
- **Europass / EDCI / EDC** — European Digital Credentials for Learning.
- **EQF** — European Qualifications Framework (Recommendation of 22 May 2017), 8-level reference scale.

| Path | evidence_class |
|---|---|
| `spec/ESCO-EUROPASS-CROSSWALK.md` (this file) | NARRACJA — competence-vocabulary mapping |
| `schemas/did-agent.schema.json` | DOWOD — requires evidence_class per skill; forbids PID |
| `conformance/golden-vectors.json` | DOWOD — skill-without-evidence_class negative vector |
