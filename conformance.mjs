#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// conformance.mjs — K0NSULT / uni0nai open commons
// Zero-dependency DID-agent conformance validator (Node >=18, builtins only).
//
// Doctrine enforced (claim <= proof, hidden engine, agents-not-people,
// soulbound != crypto, No Password Custody):
//   R1  subject_type MUST be "agent" exclusively            -> else FAIL
//   R2  no person PII fields (person/email/pesel/           -> present => FAIL
//        national_id) anywhere in the document
//   R3  every skill MUST carry evidence_class               -> missing => FAIL
//   R4  soulbound token: non_transferable===true REQUIRED,  -> any transfer
//        any transfer-shaped field                             field => FAIL
//   R5  public key only: no private-key material anywhere   -> present => FAIL
//
// This file is self-contained. `--selftest` runs embedded golden vectors
// (positive + NEGATIVE) with ZERO external files and sets the exit code.
// No network. Deterministic. No engine code, no PII, no secrets.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

// ---------------------------------------------------------------------------
// Forbidden key vocabularies (case-insensitive, matched on object KEYS only).
// Every vocabulary is passed through `norm` at construction time (F4): a listed
// spelling such as 'e-mail' MUST be stored in its normalized form ('e_mail'),
// otherwise `Set.has(norm(rawKey))` would silently miss the hyphenated variant.
// ---------------------------------------------------------------------------

// Normalizacja klucza: lowercase, spacje/myslniki -> _, ORAZ usuniecie diakrytykow
// (NFKD). Bez tego wielojezyczne pola PII (np. 'narodowość', 'płeć') omijaly denyliste.
const norm = (k) => String(k).normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/ł/gi, 'l').toLowerCase().replace(/[\s-]/g, '_');

// R2 — person-identifying fields. Their mere presence anywhere fails the doc.
// Belt to the R6 allowlist's braces: catches classic identity keys even when
// they hide NESTED under an otherwise-allowed top-level key (e.g. public_key).
// PII can hide in the VALUE of an ALLOWED key (e.g. public_key.x = "jan@example.com"),
// not only in a key name. Round-2 HIGH: scan values too, at any depth.
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const PESEL_RE = /(?<![0-9A-Za-z])\d{11}(?![0-9A-Za-z])/;
const PHONE_RE = /(?:\+\d[\d\s().-]{6,}\d)|(?<![0-9A-Za-z])\d(?:[\s().-]\d){6,}(?![0-9A-Za-z])/;
const MAX_VALUE_LEN = 4096; // H8: cap scanned length — kills O(n^2) ReDoS on hostile huge values.
function valuePII(v) {
  if (typeof v !== 'string') return null;
  if (v.length > MAX_VALUE_LEN) return `oversized-value (>${MAX_VALUE_LEN} chars)`;
  if (EMAIL_RE.test(v)) return 'email-shaped';
  if (PESEL_RE.test(v)) return '11-digit (PESEL/national-id)-shaped';
  if (PHONE_RE.test(v)) return 'phone-shaped';
  return null;
}

const PII_KEYS = new Set(
  [
    'person', 'persons', 'people',
    'full_name', 'fullname', 'first_name', 'firstname', 'given_name', 'givenname',
    'last_name', 'lastname', 'surname', 'family_name', 'familyname',
    'email', 'e-mail', 'mail', 'phone', 'tel', 'telephone', 'mobile',
    'address', 'home_address', 'residential_address',
    'pesel', 'national_id', 'national-id', 'nationalid', 'ssn',
    'dob', 'date_of_birth', 'birth_date', 'birthdate', 'birthplace',
    // H2: additional person-identifying fields the audit smuggled nested.
    'maiden_name', 'patronymic', 'middle_name', 'passport', 'passport_number',
    'tax_id', 'nip', 'iban', 'id_number', 'id_card', 'id_card_number',
    'personal_id', 'citizenship', 'gender',
    // PL + inne jezyki (denylist best-effort, NIE wyczerpujaca — patrz KNOWN-LIMITATIONS).
    'osoba', 'imie', 'nazwisko', 'nazwisko_panienskie', 'obywatelstwo', 'narodowosc',
    'pochodzenie', 'pochodzenie_etniczne', 'etnicznosc', 'wyznanie', 'religia',
    'orientacja', 'orientacja_seksualna', 'poglady', 'poglady_polityczne',
    'zdrowie', 'stan_zdrowia', 'dane_medyczne', 'adres', 'data_urodzenia',
    'miejsce_urodzenia', 'plec', 'numer_ewidencyjny', 'dowod', 'dowod_osobisty', 'paszport',
    'vorname', 'nachname', 'prenom', 'geburtsdatum',
  ].map(norm)
);

// R4 — transfer-shaped fields. Soulbound => non-transferable, so ANY transfer-
// shaped key ANYWHERE in the document fails it (F6: deep, not just token top).
// (non_transferable is the ALLOWED assertion and is handled separately.)
const TRANSFER_KEYS = new Set(
  [
    'transfer', 'transferable', 'transferrable', 'transfer_to', 'transferto',
    'transfer_hook', 'transferhook', 'approve', 'allowance', 'transfer_from',
    'transferfrom',
    // H4: transfer aliases that bypassed the soulbound guard.
    'delegate', 'delegate_to', 'delegateto', 'assign', 'assign_to', 'assignto',
    'reassign', 'grant', 'send', 'move', 'transfer_ownership', 'transferownership',
    'set_approval_for_all', 'setapprovalforall', 'sell', 'trade', 'swap',
  ].map(norm)
);

// R5 — private key material. Public-key-only tooling never holds these.
const PRIVATE_KEY_KEYS = new Set(
  [
    'private_key', 'privatekey', 'secret_key', 'secretkey',
    'seed', 'mnemonic', 'd', // 'd' is the JWK private exponent
  ].map(norm)
);

// R6 — CLOSED document shape (allowlist). A denylist can never enumerate every
// person-PII field (full_name, phone, address, date_of_birth, ...). The agent
// document is therefore closed: only these top-level keys are permitted; any
// other top-level key => FAIL. This is the structural guard that the old open
// schema (additionalProperties:true) lacked (F3).
const ALLOWED_TOP_KEYS = new Set(
  [
    'id', 'subject_type', 'public_key', 'skills', 'token',
    'rotation_ref', 'key_rotations',
  ].map(norm)
);

// H10 — storage-time id syntax MUST equal resolution-time (did-resolver), else a
// "conformant" document is unresolvable. Same DID method shape as did-resolver:
// the <model> segment MUST carry at least one digit (machine version token), so a
// bare name-shaped slug cannot masquerade as a model (agents-not-people).
const DID_RE = /^did:k0nsult:([A-Za-z0-9-]+):((?=[A-Za-z0-9._-]*[0-9])[A-Za-z0-9._-]+):([A-Za-z0-9._-]+)$/;
const ROLES = new Set(['executor', 'orchestrator', 'judge', 'observer', 'registry']);

// Deep-walk every key in the document. cb(normalizedKey, rawKey, path, value).
function walkKeys(node, cb, path = '$') {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) walkKeys(node[i], cb, `${path}[${i}]`);
    return;
  }
  for (const rawKey of Object.keys(node)) {
    const p = `${path}.${rawKey}`;
    cb(norm(rawKey), rawKey, p, node[rawKey]);
    walkKeys(node[rawKey], cb, p);
  }
}

// ---------------------------------------------------------------------------
// Core validator. Returns { verdict: 'PASS'|'FAIL', reasons: string[] }.
// A document is PASS only when it violates none of R1..R5.
// ---------------------------------------------------------------------------
// H7: bounded-recursion depth probe (short-circuits at limit+1 — safe, no overflow).
const MAX_DEPTH = 200;
function exceedsDepth(node, depth = 0) {
  if (node === null || typeof node !== 'object') return false;
  if (depth > MAX_DEPTH) return true;
  for (const v of Array.isArray(node) ? node : Object.values(node)) {
    if (exceedsDepth(v, depth + 1)) return true;
  }
  return false;
}

function validate(doc) {
  const reasons = [];

  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return { verdict: 'FAIL', reasons: ['R0: document is not a JSON object'] };
  }
  // H7: reject pathologically deep documents BEFORE any walk (stack-overflow DoS guard).
  if (exceedsDepth(doc)) {
    return { verdict: 'FAIL', reasons: [`R0: document nesting exceeds MAX_DEPTH=${MAX_DEPTH} (DoS guard)`] };
  }

  // R1 — subject_type must be exactly "agent".
  if (doc.subject_type !== 'agent') {
    reasons.push(
      `R1: subject_type must be "agent" (got ${JSON.stringify(doc.subject_type)})`
    );
  }

  // R7 (H10) — id must match the resolvable did:k0nsult method (storage == resolution).
  {
    // Two INDEPENDENT guards (R2 review): the else-if form made the role branch
    // unreachable-by-mutation, so a dead syntax guard could not be detected.
    const m = typeof doc.id === 'string' ? DID_RE.exec(doc.id) : null;
    if (m === null) {
      reasons.push(`R7: id must match did:k0nsult:<provider>:<model>:<role> (got ${JSON.stringify(doc.id)})`);
    }
    if (m !== null && !ROLES.has(m[3])) {
      reasons.push(`R7: role must be one of ${[...ROLES].join('|')} (got "${m[3]}")`);
    }
  }

  // R6 — closed document shape (allowlist). Any top-level key outside the
  // whitelist => FAIL. Closes the open-schema bypass that let unenumerated PII
  // (full_name, phone, address, ...) ride through as a "clean" agent (F3).
  for (const rawKey of Object.keys(doc)) {
    if (!ALLOWED_TOP_KEYS.has(norm(rawKey))) {
      reasons.push(
        `R6: top-level key "${rawKey}" is not in the closed agent schema allowlist`
      );
    }
  }

  // R2 / R4 / R5 — forbidden keys anywhere in the tree (deep).
  //   R2 person PII, R4 transfer-shaped fields (soulbound != crypto),
  //   R5 private key material. Deep so nothing hides under a nested object.
  walkKeys(doc, (k, _raw, path, value) => {
    if (PII_KEYS.has(k)) {
      reasons.push(`R2: person PII field forbidden at ${path} ("${k}")`);
    }
    const vp = valuePII(value);
    if (vp) {
      reasons.push(`R2: person PII value (${vp}) forbidden at ${path}`);
    }
    if (TRANSFER_KEYS.has(k)) {
      reasons.push(`R4: transfer-shaped field forbidden at ${path} ("${k}")`);
    }
    if (PRIVATE_KEY_KEYS.has(k)) {
      reasons.push(`R5: private key material forbidden at ${path} ("${k}")`);
    }
  });

  // R3 — every declared skill must carry evidence_class.
  if (doc.skills !== undefined && !Array.isArray(doc.skills)) {
    reasons.push('R3: skills must be an array (object form bypasses per-skill evidence_class)');
  }
  const skills = Array.isArray(doc.skills) ? doc.skills : [];
  for (let i = 0; i < skills.length; i++) {
    const s = skills[i];
    const hasEC =
      s && typeof s === 'object' && !Array.isArray(s) &&
      Object.prototype.hasOwnProperty.call(s, 'evidence_class') &&
      s.evidence_class !== null && s.evidence_class !== undefined &&
      String(s.evidence_class).length > 0;
    if (!hasEC) {
      reasons.push(`R3: skill[${i}] missing evidence_class`);
    }
  }

  // R4 (positive assertion) — every soulbound token MUST assert
  // non_transferable:true. The negative side (no transfer-shaped field) is
  // enforced by the DEEP TRANSFER_KEYS scan above, so a transfer_to buried in a
  // nested object under the token can no longer slip past a shallow key check.
  walkKeys(doc, (k, _raw, path, value) => {
    if (k !== 'token') return;
    // NOT mutation-isolatable, by construction (R2, stated openly): an array token
    // can never expose `non_transferable === true` (property access on an array
    // yields undefined), so the nt check below already FAILs it. This branch is
    // redundant defence-in-depth / error-message clarity, NOT a load-bearing guard.
    // Disabling it alone breaks no vector; do not read it as independently proven.
    if (Array.isArray(value)) {
      reasons.push(`R4: token at ${path} must be an object, not an array (H3: array wrapper bypasses non_transferable)`);
      return;
    }
    if (value === null || typeof value !== 'object') return;
    // non_transferable === true is REQUIRED.
    const nt = value.non_transferable ?? value.nonTransferable;
    if (nt !== true) {
      reasons.push(
        `R4: token at ${path} must set non_transferable:true (soulbound)`
      );
    }
  });

  const verdict = reasons.length === 0 ? 'PASS' : 'FAIL';
  return { verdict, reasons };
}

// ---------------------------------------------------------------------------
// Embedded golden vectors. Kept inline so --selftest needs zero external files.
// This is a SUPERSET of (not identical to) conformance/golden-vectors.json — it
// adds the mutation-isolating vectors below — so the two counts intentionally
// differ. Run the shipped file explicitly with `--vectors conformance/golden-vectors.json`.
// Every vector carries its expected verdict; the runner fails on any divergence.
// ---------------------------------------------------------------------------
const GOLDEN_VECTORS = [
  {
    name: 'valid-minimal-agent',
    expect: 'PASS',
    doc: {
      id: 'did:k0nsult:test:m0001:executor',
      subject_type: 'agent',
      public_key: { kty: 'OKP', crv: 'Ed25519', x: 'BASE64URL_PUBLIC' },
      skills: [{ name: 'osint-triage', evidence_class: 'A' }],
      token: { kind: 'soulbound', non_transferable: true },
    },
  },
  {
    name: 'valid-no-token-no-skills',
    expect: 'PASS',
    doc: {
      id: 'did:k0nsult:test:m0002:executor',
      subject_type: 'agent',
      public_key: { kty: 'OKP', crv: 'Ed25519', x: 'PUB' },
    },
  },
  {
    name: 'valid-multi-skill-all-evidence',
    expect: 'PASS',
    doc: {
      id: 'did:k0nsult:test:m0003:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: [
        { name: 'parser-burp', evidence_class: 'B' },
        { name: 'judge-panel', evidence_class: 'C' },
      ],
      token: { non_transferable: true },
    },
  },
  {
    name: 'fail-subject-type-person',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1001:executor',
      subject_type: 'person',
      public_key: { x: 'PUB' },
    },
  },
  {
    name: 'fail-subject-type-missing',
    expect: 'FAIL',
    doc: { id: 'did:k0nsult:test:m1002:executor', public_key: { x: 'PUB' } },
  },
  {
    name: 'fail-pii-email',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1003:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      email: 'someone@example.com',
    },
  },
  {
    name: 'fail-pii-pesel-nested',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1004:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      controller: { pesel: '00000000000' },
    },
  },
  {
    name: 'fail-pii-national-id',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1005:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      national_id: 'XYZ',
    },
  },
  {
    name: 'fail-pii-person-object',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1006:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      person: { name: 'redacted' },
    },
  },
  {
    name: 'fail-skill-missing-evidence-class',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1007:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: [{ name: 'osint-triage' }],
    },
  },
  {
    name: 'fail-skill-empty-evidence-class',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1008:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: [{ name: 'osint-triage', evidence_class: '' }],
    },
  },
  {
    name: 'fail-token-transferable-field',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1009:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      token: { non_transferable: true, transferable: false },
    },
  },
  {
    name: 'fail-token-transfer-hook',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1010:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      token: { non_transferable: true, transfer_to: 'did:k0nsult:test:m9999:executor' },
    },
  },
  {
    name: 'fail-token-non-transferable-not-true',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1011:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      token: { kind: 'soulbound', non_transferable: false },
    },
  },
  {
    name: 'fail-token-non-transferable-missing',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1012:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      token: { kind: 'soulbound' },
    },
  },
  {
    name: 'fail-private-key-present',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1013:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      private_key: 'MC4CAQ...',
    },
  },
  {
    name: 'fail-private-key-jwk-d-nested',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1014:executor',
      subject_type: 'agent',
      public_key: { kty: 'OKP', crv: 'Ed25519', x: 'PUB', d: 'PRIVATE_SCALAR' },
    },
  },
  {
    name: 'fail-mnemonic-seed',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1015:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      mnemonic: 'word word word ...',
    },
  },
  {
    name: 'fail-multiple-violations',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1016:executor',
      subject_type: 'human',
      email: 'x@example.com',
      private_key: 'PRIV',
      skills: [{ name: 'x' }],
      token: { transferable: true },
    },
  },
  // --- NEGATIVE regressions proving the judge's exploits are now blocked -----
  // F3: an OPEN schema + denylist let unenumerated PII ride through as a clean
  // agent. NOTE (R2 correction): `full_name` IS in PII_KEYS, so this vector trips
  // BOTH R2-key and R6 — it is a regression vector, NOT an isolating one. The
  // earlier claim that it FAILs "solely via R6" was false; the R6-isolating vector
  // is `fail-r6-unknown-top-key` below (benign, non-denylisted key).
  {
    name: 'fail-allowlist-full-name-top',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1018:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      full_name: 'Jane Doe',
    },
  },
  // F4: the denylist Set is now built through `norm`, so the hyphenated
  // spelling 'e-mail' (=> 'e_mail') is caught. Nested under public_key so the
  // R6 top-level allowlist does NOT fire — only the normalized R2 denylist can.
  // PASSED before the F4 fix (Set held 'email', never 'e_mail').
  {
    name: 'fail-pii-email-hyphen-nested',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1019:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB', 'e-mail': 'someone@example.com' },
    },
  },
  // F6: transfer-shaped fields were only checked on the token's OWN keys, so a
  // transfer_to buried one level deeper (token.policy.transfer_to) escaped.
  // Now the deep TRANSFER_KEYS scan catches it. PASSED before the F6 fix.
  {
    name: 'fail-token-transfer-nested',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1020:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      token: { non_transferable: true, policy: { transfer_to: 'did:k0nsult:test:m9999:executor' } },
    },
  },
  // --- ISOLATING vectors: each FAILs via exactly ONE guard (mutation-verified) --
  // (a) R2 value-PII under an ALLOWED key. `public_key` is allowlisted and `x` is
  //     not a PII key — the ONLY violation is the valuePII VALUE scan. Comment out
  //     `const vp = valuePII(value); if (vp) …` and this PASSES.
  {
    name: 'fail-r2-value-pii-under-allowed-key',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1021:executor',
      subject_type: 'agent',
      public_key: { x: 'someone@example.com' },
    },
  },
  // (b) R2 nested PII KEY under an allowed key, with a non-PII-shaped value
  //     ("Kowalski" trips no value regex). The ONLY violation is the deep
  //     PII_KEYS name check. Comment out `if (PII_KEYS.has(k)) …` and this PASSES.
  {
    name: 'fail-r2-nested-pii-key-under-allowed-key',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1022:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB', surname: 'Kowalski' },
    },
  },
  // (c) R6 closed-schema allowlist. `experimental_field` is not in the allowlist
  //     and is not a PII/transfer/private key — the ONLY violation is R6. Comment
  //     out the R6 top-level loop and this PASSES.
  {
    name: 'fail-r6-unknown-top-key',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1023:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      experimental_field: 'x',
    },
  },
  // (e) R3 skills-must-be-an-ARRAY. In OBJECT form the per-skill loop iterates
  //     nothing, so every declared skill escapes the evidence_class requirement.
  //     Nothing else in the document is violated, so the `!Array.isArray(doc.skills)`
  //     branch is the ONLY guard here — flip it to `if (false)` and this PASSES.
  //     (R2 mutation testing found this branch had NO vector at all.)
  {
    name: 'fail-r3-skills-object-form',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1025:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: { first: { name: 'osint-triage' } },
    },
  },
  // (f) R0 MAX_DEPTH DoS guard. Audit R2 (LOW) found this guard had NO vector:
  //     removing it left the suite green. The document below is valid in every
  //     other respect — correct id, subject_type, public_key, no PII, no forbidden
  //     key — so the depth check is the ONLY thing that can reject it. Flip
  //     `if (exceedsDepth(doc))` to `if (false)` and this vector PASSES.
  {
    name: 'fail-r0-nesting-exceeds-max-depth',
    expect: 'FAIL',
    doc: (() => {
      let deep = { leaf: 1 };
      for (let i = 0; i < MAX_DEPTH + 20; i++) deep = { nested: deep };
      return {
        id: 'did:k0nsult:test:m1027:executor',
        subject_type: 'agent',
        public_key: { x: 'PUB' },
        skills: [{ name: 'osint-triage', evidence_class: 'DOWOD', deep }],
      };
    })(),
  },
  // (g) H8 oversized-value cap. Also had NO vector (audit R2, LOW). The value is
  //     benign — a run of 'a' — so it matches no PII shape and violates nothing
  //     else; only the `v.length > MAX_VALUE_LEN` branch can reject it. This is
  //     the ReDoS guard: without the cap, hostile megabyte-scale values are fed
  //     to the scanning regexes.
  {
    name: 'fail-h8-oversized-value',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1028:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: [{ name: 'a'.repeat(MAX_VALUE_LEN + 1), evidence_class: 'DOWOD' }],
    },
  },
  // (h) valuePII 11-digit (PESEL/national-id) branch. Audyt roju (2/3, POTWIERDZONY):
  //     galaz PESEL w valuePII nie miala wektora izolujacego — wylaczenie jej dawalo
  //     selftest zielony. Wartosc ponizej to 11 cyfr z granicami niealfanumerycznymi
  //     pod DOZWOLONYM kluczem (name) — nie oversized, nie klucz PII, nie inna regula;
  //     jedyna mozliwa przyczyna FAIL to galaz PESEL_RE. Wylacz linie `if (PESEL_RE...)`
  //     i ten wektor PASSES.
  {
    name: 'fail-pii-pesel-value-isolating',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1029:executor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
      skills: [{ name: 'ref 90010112345 end', evidence_class: 'DOWOD' }],
    },
  },
  // (d1) R7 id-syntax. A non-k0nsult method id — DID_RE.exec is null, so the ONLY
  //      violation is the R7 syntax branch. Comment out the R7 block and this PASSES.
  {
    name: 'fail-r7-bad-did-syntax',
    expect: 'FAIL',
    doc: {
      id: 'did:web:example.com',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
    },
  },
  // (d2) R7 role. Valid DID syntax but a role outside the spec enum
  //      (executor|orchestrator|judge|observer|registry) — the ONLY violation is the
  //      R7 role branch. Flip that branch to `if (false)` and this PASSES.
  {
    name: 'fail-r7-bad-role',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:test:m1024:auditor',
      subject_type: 'agent',
      public_key: { x: 'PUB' },
    },
  },
];

// ---------------------------------------------------------------------------
// Runner over a vector set. Returns { total, ok, failures[] }.
// ---------------------------------------------------------------------------
function runVectors(vectors) {
  const failures = [];
  let ok = 0;
  for (const v of vectors) {
    const { verdict, reasons } = validate(v.doc);
    if (verdict === v.expect) {
      ok++;
    } else {
      failures.push({ name: v.name, expect: v.expect, got: verdict, reasons });
    }
  }
  return { total: vectors.length, ok, failures };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function printUsage() {
  process.stdout.write(
    [
      'conformance.mjs — DID-agent conformance validator (zero-dep)',
      '',
      'Usage:',
      '  node conformance.mjs --selftest',
      '      Run embedded golden vectors (positive + negative). exit 0 if every',
      '      vector matches its expected verdict, exit 1 otherwise.',
      '',
      '  node conformance.mjs --vectors <path>',
      '      Run an external golden-vectors.json (same schema as embedded set).',
      '',
      '  node conformance.mjs <did-agent.json>',
      '      Validate a single document. Prints PASS/FAIL + reasons.',
      '      exit 0 on PASS, exit 1 on FAIL.',
      '',
    ].join('\n')
  );
}

function main(argv) {
  const args = argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printUsage();
    return args.length === 0 ? 1 : 0;
  }

  if (args.includes('--selftest')) {
    const { total, ok, failures } = runVectors(GOLDEN_VECTORS);
    for (const v of GOLDEN_VECTORS) {
      const { verdict } = validate(v.doc);
      const pass = verdict === v.expect;
      process.stdout.write(
        `${pass ? 'ok  ' : 'FAIL'}  ${v.name}  expect=${v.expect} got=${verdict}\n`
      );
    }
    process.stdout.write(`\nselftest: ${ok}/${total} vectors matched expect\n`);
    if (failures.length) {
      process.stdout.write('DIVERGENCES:\n');
      for (const f of failures) {
        process.stdout.write(
          `  ${f.name}: expect=${f.expect} got=${f.got} :: ${f.reasons.join('; ')}\n`
        );
      }
      return 1;
    }
    return 0;
  }

  const vi = args.indexOf('--vectors');
  if (vi !== -1) {
    const path = args[vi + 1];
    if (!path) {
      process.stderr.write('error: --vectors requires a path\n');
      return 1;
    }
    let vectors;
    try {
      vectors = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
      process.stderr.write(`error: cannot read/parse ${path}: ${e.message}\n`);
      return 1;
    }
    if (!Array.isArray(vectors)) {
      process.stderr.write('error: vectors file must be a JSON array\n');
      return 1;
    }
    const { total, ok, failures } = runVectors(vectors);
    for (const v of vectors) {
      const { verdict } = validate(v.doc);
      const pass = verdict === v.expect;
      process.stdout.write(
        `${pass ? 'ok  ' : 'FAIL'}  ${v.name || '(unnamed)'}  expect=${v.expect} got=${verdict}\n`
      );
    }
    process.stdout.write(`\nvectors: ${ok}/${total} matched expect\n`);
    return failures.length ? 1 : 0;
  }

  // Single document mode.
  const path = args[0];
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    process.stderr.write(`error: cannot read/parse ${path}: ${e.message}\n`);
    return 1;
  }
  const { verdict, reasons } = validate(doc);
  process.stdout.write(`${verdict}\n`);
  for (const r of reasons) process.stdout.write(`  - ${r}\n`);
  return verdict === 'PASS' ? 0 : 1;
}

// Exported for potential library use; harmless under direct execution.
export { validate, runVectors, GOLDEN_VECTORS };

// Run only when invoked directly (not when imported).
const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  process.exit(main(process.argv));
}
