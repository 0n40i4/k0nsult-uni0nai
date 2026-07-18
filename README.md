# k0nsult-uni0nai

The **agent-federation interoperability contract** of the K0NSULT open commons —
the schemas an implementer codes *against* so EU-hosted agents from different
vendors can identify, describe and call each other without a non-EU broker.

This repository is the **contract, not the engine.** The federation runtime
(`agent-registry.js`, `agents-management.js`, `did-resolver.js`, `skill-lab.js`, …)
is proprietary k0nsult.cloud code and is **deliberately not included**.

> **Doctrine:** `agents-not-people` — DIDs and skills belong to **agents**, never
> natural persons; only agents are scored. `claim ≤ proof`.

## Contents (`contract/`)

| File | What it is |
|---|---|
| `acp-schema.json` | **Agent Communication Protocol (ACP 1.0)** — a 4-layer envelope: protocol (schema/version/signature), context (session/state), constraint (permissions/latency/cost), intent (action/params/outcome). Messages carry `did:k0nsult:*` sender/receiver. |
| `skills-registry.json` | **Skill taxonomy** — agent skills with `id`, `name`, `description`, `owner_did` (an agent), `version`, usage metrics. The shared vocabulary for capability routing. |

## The three interoperability artefacts (COM(2026)503 building block)
1. **DID-based agent identity** — `did:k0nsult:<provider>:<model>:<role>` (see ACP sender/receiver).
2. **Open skill taxonomy** — `skills-registry.json`.
3. **Capability routing** — an agent is selected by the skill it declares; ACP layer 4 (intent) carries the requested action. The routing *policy* is engine-side; the *contract* it honours is here.

## Implementing against this contract
Code your own runtime that (a) resolves `did:k0nsult:*` identities, (b) advertises
skills in the taxonomy shape, and (c) exchanges ACP-1.0 messages. You do **not**
need the K0NSULT engine to interoperate — that is the point of an open contract.

## Supply chain
`sbom.json` via [`k0nsult-tools`](../k0nsult-tools).

## License
Apache-2.0 (explicit patent grant, Section 3). See `LICENSE` and `NOTICE`.
