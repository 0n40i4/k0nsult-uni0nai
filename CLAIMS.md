# CLAIMS.md — public claim register (k0nsult-uni0nai)

Generated from [`k0nsult-tools/docs/CLAIMS-TEMPLATE.md`](https://github.com/0n40i4/k0nsult-tools/blob/master/docs/CLAIMS-TEMPLATE.md)
(OSS-0-06).

| id | statement | class | proof_ref / roadmap_ref | repo_status_ref | verified_at |
|---|---|---|---|---|---|
| `clm-0001` | This repository is the contract, not the engine — the federation runtime is a private engine (proprietary k0nsult.cloud code), deliberately not included. | NARRACJA | — (negative/scope claim: absence of engine code, true by omission from this repo's own file list, not independently checkable against the private engine from here) | — | 2026-08-02 |
| `clm-0002` | `contract/acp-schema.json` defines a 4-layer ACP 1.0 envelope (protocol/context/constraint/intent), with messages carrying `did:k0nsult:*` sender/receiver. | DOWOD | `contract/acp-schema.json` present in this repo (JSON Schema artefact, directly inspectable) | — | 2026-08-02 |
| `clm-0003` | `contract/skills-registry.json` carries no live records and no telemetry — it is a synthetic example plus a shape contract. | DOWOD | `contract/skills-registry.json` present; `README.md`:19 states this explicitly ("carries no live records and no telemetry") — checkable by inspecting the file's own content | — | 2026-08-02 |
| `clm-0004` | This repo (`k0nsult-uni0nai`), `unionai-core`, and `uni0n` are three separate repos with three separate roles (public contract / private production engine / public testnet) and are not interchangeable. | NARRACJA | `README.md` "Relation to unionai-core / uni0n" section (added `OSS-1-17`, this same wave), sourced from `gh api repos/0n40i4/unionai-core --jq .description` and `gh api repos/0n40i4/uni0n --jq .description` fetched live 2026-08-02 — the underlying GitHub descriptions are DOWOD (directly fetched), but the *relationship framing itself* (which repo is "the" contract vs "the" engine) is asserted, not independently arbitrable from outside the organisation, hence NARRACJA per `OSS-2-11`'s own instruction pending `K0S-014` (`OSS-2-23`, out of this agent's non-ACK scope) | — | 2026-08-02 |
| `clm-0005` | You do not need the K0NSULT engine to interoperate with this contract — implementing DID resolution + skill taxonomy + ACP-1.0 exchange is sufficient. | NARRACJA | — (a design claim about interoperability; no independent third-party implementation exists in this repo to point at as proof that it actually works end-to-end) | — | 2026-08-02 |

## Placeholder row (copy for new claims)

| id | statement | class | proof_ref / roadmap_ref | repo_status_ref | verified_at |
|---|---|---|---|---|---|
| `clm-00NN` | *(exact claim text)* | *(DOWOD\|GAP\|NARRACJA)* | *(ref, or "—" if NARRACJA)* | *(optional, or "—")* | *(YYYY-MM-DD)* |
