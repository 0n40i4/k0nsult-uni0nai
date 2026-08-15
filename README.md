# k0nsult-uni0nai

The **agent-federation interoperability contract** of the K0NSULT open commons —
the schemas an implementer codes *against* so EU-hosted agents from different
vendors can identify, describe and call each other without a non-EU broker.

This repository is the **contract, not the engine.** The federation runtime is a
**private engine** (proprietary k0nsult.cloud code) and is **deliberately not
included** — no engine source, no module topology.

> **Doctrine:** `agents-not-people` — DIDs and skills belong to **agents**, never
> natural persons; only agents are scored. `claim ≤ proof`.

## Contents (`contract/`)

| File | What it is |
|---|---|
| `acp-schema.json` | **Agent Communication Protocol (ACP 1.0)** — a 4-layer envelope: protocol (schema/version/signature), context (session/state), constraint (permissions/latency/cost), intent (action/params/outcome). Messages carry `did:k0nsult:*` sender/receiver. |
| `skills-registry.json` | **Skill taxonomy** — a **synthetic example** plus the per-record shape (`id`, `name`, `description`, `owner_did` (an agent), `version`, `evidence_class`). The shared vocabulary for capability routing; carries no live records and no telemetry. |

## The three interoperability artefacts (COM(2026)503 building block)
1. **DID-based agent identity** — `did:k0nsult:<provider>:<model>:<role>` (see ACP sender/receiver).
2. **Open skill taxonomy** — `skills-registry.json`.
3. **Capability routing** — an agent is selected by the skill it declares; ACP layer 4 (intent) carries the requested action. The routing *policy* is engine-side; the *contract* it honours is here.

## Implementing against this contract
Code your own runtime that (a) resolves `did:k0nsult:*` identities, (b) advertises
skills in the taxonomy shape, and (c) exchanges ACP-1.0 messages. You do **not**
need the K0NSULT engine to interoperate — that is the point of an open contract.

## Relation to `unionai-core` / `uni0n` (three similarly-named repos, three different roles)
Three repositories in the `0n40i4` GitHub account share the "unionai"/"uni0n" name root.
They are **not interchangeable** and this repo does not run any of the other two:

| Repo | Role | Visibility | GitHub description (verbatim, 2026-08-02) |
|---|---|---|---|
| **`k0nsult-uni0nai`** (this repo) | The interoperability **contract/schema** — ACP envelope + skill taxonomy. No runtime, no engine. | public (OSS) | *(this README)* |
| [`unionai-core`](https://github.com/0n40i4/unionai-core) | The **private, proprietary production engine** — "recovered production source v0.3.0". Explicitly disambiguates itself from both other repos in its own description. | private | "UNIONAI core — odzyskane zrodlo produkcyjne v0.3.0 (2026-07-22). NIE jest to k0nsult-uni0nai (commons/spec) ani uni0n (testnet)." |
| [`uni0n`](https://github.com/0n40i4/uni0n) | A **public testnet** federation layer (research initiative), run under a separate legal umbrella (Grass Roots Lobbing). | public | "UNIONAI Omega Infinity - public testnet of an open AI-agent federation layer (research initiative). DID-lite trust, memory anchoring, semantic routing, EU AI Act readiness (NOT certification/compliance). Status: GO CONTROLLED / PUBLIC TESTNET." |

`unionai-core` already disambiguates itself from this repo and from `uni0n` in its own
GitHub description; this section closes the gap in the other direction (K0S-014) so a
reader landing on `k0nsult-uni0nai` first gets the same clarity without having to find
`unionai-core` independently. If you are looking for a **running** federation
endpoint, you want `uni0n` (public testnet) or the private `unionai-core` engine — not
this repo, which is the contract those engines are expected to honour.

## Supply chain
`sbom.json` via [`k0nsult-tools`](../k0nsult-tools).

## License
Apache-2.0 (explicit patent grant, Section 3). See `LICENSE` and `NOTICE`.
