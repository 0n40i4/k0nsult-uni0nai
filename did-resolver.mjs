#!/usr/bin/env node
// did-resolver.mjs — K0NSULT / uni0nai open commons
// Zero-dependency did:k0nsult resolver / validator / rotator
// (Node >=18, builtins only: node:crypto, node:fs, node:process, node:url).
//
// CONTRACT, NOT ENGINE. This is a clean-room, offline reference resolver for the
// `did:k0nsult` method (spec/DID-METHOD-SPEC.md). It carries ZERO k0nsult.cloud
// engine code, ZERO PII, ZERO secrets.
//
// Doctrine enforced:
//   claim <= proof           — a document advertises only what its shape proves.
//   agents-not-people        — subject is ALWAYS an agent; no natural-person PID.
//   soulbound != crypto      — identity anchor, not a wallet/asset.
//   No Password Custody       — the tool NEVER generates, stores, asks for or
//                               emits a private key. Rotation carries PUBLIC keys
//                               only; signing happens with the operator, off-tool.
//
// Public surface:
//   parse(did)                     -> { provider, model, role }   (throws on bad DID)
//   validate(didDocument)          -> { verdict:'PASS'|'FAIL', reasons:[] }
//   rotate(doc, newPublicKey, tsISO) -> new document (public-key chain; no secret)
//   fingerprint(publicKey)         -> 'sha256:<hex>' (stable, deterministic)
//
// `--selftest` runs embedded POSITIVE and NEGATIVE vectors with ZERO external
// files, sets exit(0) on all-pass and exit(1) on any divergence. Offline,
// deterministic. No network. No engine code, no PII, no secrets.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

// ---------------------------------------------------------------------------
// DID syntax (aligned with schemas/did-agent.schema.json + spec §2 ABNF).
//   did:k0nsult:<provider>:<model>:<role>
// ---------------------------------------------------------------------------
const DID_RE =
  /^did:k0nsult:([A-Za-z0-9-]+):([A-Za-z0-9._-]+):([A-Za-z0-9._-]+)$/;

// spec §2: role is drawn from the federation role enum.
const ROLES = new Set(['executor', 'orchestrator', 'judge', 'observer', 'registry']);

// ---------------------------------------------------------------------------
// Forbidden key vocabularies (case-insensitive, matched on object KEYS only).
// Mirror of conformance.mjs so resolution-time invariants == storage-time ones.
// ---------------------------------------------------------------------------
const PII_KEYS = new Set([
  'person', 'email', 'pesel', 'national_id', 'nationalid', 'ssn',
]);
const PRIVATE_KEY_KEYS = new Set([
  'private_key', 'privatekey', 'secret_key', 'secretkey', 'secret',
  'seed', 'mnemonic', 'd', // 'd' is the JWK private exponent/scalar
]);

const norm = (k) => String(k).toLowerCase().replace(/[\s-]/g, '_');

class K0Error extends Error {}

// Deep-walk every key. cb(normalizedKey, rawKey, path, value).
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

// First path at which private-key material appears, or null.
function firstPrivatePath(node) {
  let hit = null;
  walkKeys(node, (k, _raw, path) => {
    if (hit === null && PRIVATE_KEY_KEYS.has(k)) hit = `${path} ("${k}")`;
  });
  return hit;
}

// Deterministic deep clone via structured recursion (no JSON round-trip
// dependence on key order; plain data only — documents are pure JSON).
function deepClone(v) {
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(deepClone);
  const out = {};
  for (const k of Object.keys(v)) out[k] = deepClone(v[k]);
  return out;
}

// Canonical JSON with recursively sorted keys — stable fingerprint input.
function stableStringify(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
}

// ---------------------------------------------------------------------------
// parse(did) -> { provider, model, role }
// Throws K0Error on any identifier that fails §2 syntax.
// ---------------------------------------------------------------------------
function parse(did) {
  if (typeof did !== 'string') {
    throw new K0Error(`parse: DID must be a string (got ${typeof did})`);
  }
  const m = DID_RE.exec(did);
  if (!m) {
    throw new K0Error(`parse: invalidDid — does not match did:k0nsult:<provider>:<model>:<role> (${JSON.stringify(did)})`);
  }
  const [, provider, model, role] = m;
  return { provider, model, role };
}

// ---------------------------------------------------------------------------
// validate(didDocument) -> { verdict, reasons }
// Resolution-time invariants (spec §5), narrowed to this resolver's remit:
//   V1  id present and matches the DID syntax.
//   V2  subject_type === 'agent' EXCLUSIVELY.
//   V3  public_key present (object) — public verification material.
//   V4  HARD: no private-key material ANYWHERE (No Password Custody).
//   V5  no natural-person PID ANYWHERE (agents-not-people).
// PASS only when none are violated.
// ---------------------------------------------------------------------------
function validate(doc) {
  const reasons = [];

  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    return { verdict: 'FAIL', reasons: ['V0: document is not a JSON object'] };
  }

  // V1 — id syntax.
  if (typeof doc.id !== 'string' || !DID_RE.test(doc.id)) {
    reasons.push(`V1: id must match did:k0nsult:<provider>:<model>:<role> (got ${JSON.stringify(doc.id)})`);
  } else {
    // role must be a known federation role (spec §2).
    const { role } = parse(doc.id);
    if (!ROLES.has(role)) {
      reasons.push(`V1: role "${role}" is not a federation role (${[...ROLES].join('|')})`);
    }
  }

  // V2 — subject_type must be exactly "agent".
  if (doc.subject_type !== 'agent') {
    reasons.push(`V2: subject_type must be "agent" exclusively (got ${JSON.stringify(doc.subject_type)})`);
  }

  // V3 — public key material present.
  if (doc.public_key === null || typeof doc.public_key !== 'object' || Array.isArray(doc.public_key)) {
    reasons.push('V3: public_key (object) is required — public verification material');
  }

  // V4 / V5 — forbidden keys anywhere in the tree.
  walkKeys(doc, (k, _raw, path) => {
    if (PRIVATE_KEY_KEYS.has(k)) {
      reasons.push(`V4: private key material forbidden at ${path} ("${k}") — No Password Custody`);
    }
    if (PII_KEYS.has(k)) {
      reasons.push(`V5: person PID field forbidden at ${path} ("${k}") — agents-not-people`);
    }
  });

  return { verdict: reasons.length === 0 ? 'PASS' : 'FAIL', reasons };
}

// ---------------------------------------------------------------------------
// fingerprint(publicKey) -> 'sha256:<hex>'  (deterministic, order-independent)
// ---------------------------------------------------------------------------
function fingerprint(publicKey) {
  return 'sha256:' + createHash('sha256').update(stableStringify(publicKey)).digest('hex');
}

// ---------------------------------------------------------------------------
// rotate(doc, newPublicKey, tsISO) -> new document
// spec §6.2: replace the active verification key WITHOUT any secret leaving the
// operator. The tool touches PUBLIC keys only:
//   - refuses any newPublicKey carrying private material (No Password Custody);
//   - preserves the prior public key via an append-only rotation event;
//   - sets rotation_ref (top-level) to the immediately-prior key's fingerprint;
//   - NEVER reads, copies or emits a private key (there is none to touch).
// The returned document is a fresh object; the input is not mutated.
// ---------------------------------------------------------------------------
function rotate(doc, newPublicKey, tsISO) {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new K0Error('rotate: doc must be a JSON object');
  }
  if (newPublicKey === null || typeof newPublicKey !== 'object' || Array.isArray(newPublicKey)) {
    throw new K0Error('rotate: newPublicKey must be a public-key object');
  }
  // No Password Custody: refuse to introduce ANY private material.
  const priv = firstPrivatePath(newPublicKey);
  if (priv) {
    throw new K0Error(`rotate: newPublicKey carries private material at ${priv} — No Password Custody (public keys only)`);
  }
  if (typeof tsISO !== 'string' || Number.isNaN(Date.parse(tsISO))) {
    throw new K0Error('rotate: tsISO must be an ISO-8601 timestamp string');
  }
  const prevPublicKey = doc.public_key;
  if (prevPublicKey === null || typeof prevPublicKey !== 'object' || Array.isArray(prevPublicKey)) {
    throw new K0Error('rotate: source document has no public_key to rotate from');
  }

  const prevRef = fingerprint(prevPublicKey);
  const event = {
    previous_public_key: deepClone(prevPublicKey),
    new_public_key: deepClone(newPublicKey),
    rotation_ref: prevRef, // fingerprint of the key being retired
    rotated_at: tsISO,
  };

  const log = Array.isArray(doc.key_rotations) ? doc.key_rotations.map(deepClone) : [];
  log.push(event);

  const next = deepClone(doc);
  next.public_key = deepClone(newPublicKey); // new ACTIVE public key
  next.rotation_ref = prevRef;               // pointer to the immediately-prior key
  next.key_rotations = log;                  // append-only chain of public-key events
  return next;
}

// ---------------------------------------------------------------------------
// Embedded selftest vectors — POSITIVE + NEGATIVE, zero external files.
// ---------------------------------------------------------------------------

// -- parse() cases -----------------------------------------------------------
const PARSE_CASES = [
  {
    name: 'parse-valid-judge',
    expect: 'ok',
    did: 'did:k0nsult:claude:opus-4.7-1m:judge',
    want: { provider: 'claude', model: 'opus-4.7-1m', role: 'judge' },
  },
  {
    name: 'parse-valid-executor',
    expect: 'ok',
    did: 'did:k0nsult:mistral:large-2:executor',
    want: { provider: 'mistral', model: 'large-2', role: 'executor' },
  },
  {
    name: 'parse-valid-local-registry',
    expect: 'ok',
    did: 'did:k0nsult:local:llama.3_8b:registry',
    want: { provider: 'local', model: 'llama.3_8b', role: 'registry' },
  },
  { name: 'parse-fail-wrong-method', expect: 'throw', did: 'did:web:example.com:agent' },
  { name: 'parse-fail-missing-role', expect: 'throw', did: 'did:k0nsult:claude:opus-4.7' },
  { name: 'parse-fail-empty-segment', expect: 'throw', did: 'did:k0nsult:claude::judge' },
  { name: 'parse-fail-trailing-colon', expect: 'throw', did: 'did:k0nsult:claude:opus:judge:' },
  { name: 'parse-fail-not-a-string', expect: 'throw', did: 42 },
];

// -- validate() cases --------------------------------------------------------
const VALIDATE_CASES = [
  {
    name: 'validate-pass-minimal-agent',
    expect: 'PASS',
    doc: {
      id: 'did:k0nsult:claude:opus-4.7-1m:judge',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'BASE64URL_PUBLIC' },
    },
  },
  {
    name: 'validate-pass-with-skills',
    expect: 'PASS',
    doc: {
      id: 'did:k0nsult:mistral:large-2:executor',
      subject_type: 'agent',
      public_key: { type: 'ecdsa-p256', value: 'PUB' },
      skills: [{ name: 'osint-triage', evidence_class: 'A' }],
    },
  },
  {
    name: 'validate-fail-private-key-top',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'PUB' },
      private_key: 'MC4CAQ...',
    },
  },
  {
    name: 'validate-fail-jwk-d-nested',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'agent',
      public_key: { kty: 'OKP', crv: 'Ed25519', x: 'PUB', d: 'PRIVATE_SCALAR' },
    },
  },
  {
    name: 'validate-fail-mnemonic',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'PUB' },
      mnemonic: 'word word word ...',
    },
  },
  {
    name: 'validate-fail-subject-person',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'person',
      public_key: { type: 'ed25519', value: 'PUB' },
    },
  },
  {
    name: 'validate-fail-subject-missing',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      public_key: { type: 'ed25519', value: 'PUB' },
    },
  },
  {
    name: 'validate-fail-no-public-key',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'agent',
    },
  },
  {
    name: 'validate-fail-pii-email',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:judge',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'PUB' },
      email: 'someone@example.com',
    },
  },
  {
    name: 'validate-fail-bad-did-syntax',
    expect: 'FAIL',
    doc: {
      id: 'did:web:example.com',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'PUB' },
    },
  },
  {
    name: 'validate-fail-unknown-role',
    expect: 'FAIL',
    doc: {
      id: 'did:k0nsult:claude:opus:overlord',
      subject_type: 'agent',
      public_key: { type: 'ed25519', value: 'PUB' },
    },
  },
];

// -- rotate() cases (behavioural asserts) ------------------------------------
const ROTATE_CASES = [
  {
    name: 'rotate-produces-public-key-chain',
    run() {
      const base = {
        id: 'did:k0nsult:claude:opus-4.7-1m:judge',
        subject_type: 'agent',
        public_key: { type: 'ed25519', value: 'PUB_K0' },
      };
      const k1 = { type: 'ed25519', value: 'PUB_K1' };
      const k2 = { type: 'ed25519', value: 'PUB_K2' };

      const r1 = rotate(base, k1, '2026-07-19T10:00:00Z');
      const r2 = rotate(r1, k2, '2026-07-19T11:00:00Z');

      // input not mutated
      if (base.public_key.value !== 'PUB_K0') return fail('base mutated');
      if (base.key_rotations !== undefined) return fail('base gained key_rotations');

      // active key advanced
      if (r2.public_key.value !== 'PUB_K2') return fail('active key not K2');

      // append-only chain of PUBLIC keys, length 2
      const log = r2.key_rotations;
      if (!Array.isArray(log) || log.length !== 2) return fail('chain length != 2');

      // event 0: K0 -> K1, event 1: K1 -> K2  (links form a chain)
      if (log[0].previous_public_key.value !== 'PUB_K0') return fail('e0.prev != K0');
      if (log[0].new_public_key.value !== 'PUB_K1') return fail('e0.new != K1');
      if (log[1].previous_public_key.value !== 'PUB_K1') return fail('e1.prev != K1');
      if (log[1].new_public_key.value !== 'PUB_K2') return fail('e1.new != K2');

      // rotation_ref links to the fingerprint of the retired key
      if (log[0].rotation_ref !== fingerprint(base.public_key)) return fail('e0 ref mismatch');
      if (log[1].rotation_ref !== fingerprint(k1)) return fail('e1 ref mismatch');
      if (r2.rotation_ref !== fingerprint(k1)) return fail('top ref != fp(K1)');

      // NO private-key material introduced anywhere by rotation
      if (firstPrivatePath(r2) !== null) return fail('private material leaked into rotated doc');

      // rotated document still validates as a resolvable agent doc
      const { verdict } = validate(r2);
      if (verdict !== 'PASS') return fail('rotated doc fails validate');

      return ok();
    },
  },
  {
    name: 'rotate-rejects-private-material',
    run() {
      const base = {
        id: 'did:k0nsult:claude:opus:judge',
        subject_type: 'agent',
        public_key: { type: 'ed25519', value: 'PUB_K0' },
      };
      // Attempt to rotate to a "public key" that smuggles a private scalar.
      try {
        rotate(base, { type: 'ed25519', value: 'PUB', d: 'PRIVATE_SCALAR' }, '2026-07-19T10:00:00Z');
        return fail('rotate accepted private material (No Password Custody breach)');
      } catch (e) {
        if (e instanceof K0Error) return ok();
        return fail(`unexpected error type: ${e.message}`);
      }
    },
  },
  {
    name: 'rotate-rejects-bad-timestamp',
    run() {
      const base = {
        id: 'did:k0nsult:claude:opus:judge',
        subject_type: 'agent',
        public_key: { type: 'ed25519', value: 'PUB_K0' },
      };
      try {
        rotate(base, { type: 'ed25519', value: 'PUB_K1' }, 'not-a-date');
        return fail('rotate accepted a non-ISO timestamp');
      } catch (e) {
        return e instanceof K0Error ? ok() : fail(`unexpected error: ${e.message}`);
      }
    },
  },
];

function ok(detail = '') { return { ok: true, detail }; }
function fail(detail) { return { ok: false, detail }; }

// ---------------------------------------------------------------------------
// Selftest runner.
// ---------------------------------------------------------------------------
function runSelftest(out) {
  let total = 0;
  let passed = 0;

  const line = (pass, name, detail) => {
    total++;
    if (pass) passed++;
    out(`${pass ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  :: ' + detail : ''}\n`);
  };

  // parse
  for (const c of PARSE_CASES) {
    if (c.expect === 'ok') {
      try {
        const got = parse(c.did);
        const match =
          got.provider === c.want.provider &&
          got.model === c.want.model &&
          got.role === c.want.role;
        line(match, c.name, match ? '' : `got ${JSON.stringify(got)}`);
      } catch (e) {
        line(false, c.name, `threw: ${e.message}`);
      }
    } else {
      let threw = false;
      try { parse(c.did); } catch (e) { threw = e instanceof K0Error; }
      line(threw, c.name, threw ? '' : 'expected throw, none');
    }
  }

  // validate
  for (const c of VALIDATE_CASES) {
    const { verdict } = validate(c.doc);
    line(verdict === c.expect, c.name, verdict === c.expect ? '' : `expect=${c.expect} got=${verdict}`);
  }

  // rotate
  for (const c of ROTATE_CASES) {
    let res;
    try { res = c.run(); } catch (e) { res = fail(`threw: ${e.message}`); }
    line(res.ok, c.name, res.ok ? '' : res.detail);
  }

  out(`\nselftest: ${passed}/${total} cases passed\n`);
  return passed === total;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function printUsage(out) {
  out(
    [
      'did-resolver.mjs — did:k0nsult resolver / validator / rotator (zero-dep)',
      '',
      'Usage:',
      '  node did-resolver.mjs --selftest',
      '      Run embedded positive + negative vectors. exit 0 if all pass, else 1.',
      '',
      '  node did-resolver.mjs --parse <did>',
      '      Print { provider, model, role } for a did:k0nsult identifier.',
      '',
      '  node did-resolver.mjs <did-document.json>',
      '      Validate a document. Prints PASS/FAIL + reasons. exit 0/1.',
      '',
    ].join('\n') + '\n'
  );
}

function main(argv) {
  const args = argv.slice(2);
  const out = (s) => process.stdout.write(s);
  const err = (s) => process.stderr.write(s);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printUsage(out);
    return args.length === 0 ? 1 : 0;
  }

  if (args.includes('--selftest')) {
    return runSelftest(out) ? 0 : 1;
  }

  const pi = args.indexOf('--parse');
  if (pi !== -1) {
    const did = args[pi + 1];
    try {
      out(JSON.stringify(parse(did)) + '\n');
      return 0;
    } catch (e) {
      err(`${e.message}\n`);
      return 1;
    }
  }

  // Single-document validation mode.
  const path = args[0];
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    err(`error: cannot read/parse ${path}: ${e.message}\n`);
    return 1;
  }
  const { verdict, reasons } = validate(doc);
  out(`${verdict}\n`);
  for (const r of reasons) out(`  - ${r}\n`);
  return verdict === 'PASS' ? 0 : 1;
}

// Library exports.
export { parse, validate, rotate, fingerprint, K0Error };

// Run only when invoked directly.
const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  process.exit(main(process.argv));
}
