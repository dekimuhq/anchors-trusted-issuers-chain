#!/usr/bin/env node
/**
 * Hand-rolled JCS round-trip sanity check for `scripts/lib/canonical.mjs`.
 * Run with `node scripts/test-canonical.mjs`. Exits 1 on any divergence.
 *
 * This is NOT a substitute for the upstream test suite in
 * `@dekimuhq/anchors-envelope` — it just guards against accidental drift in
 * the copy we ship here.
 */

import { canonicalize } from "./lib/canonical.mjs";

const cases = [
  {
    name: "empty object",
    input: {},
    expected: "{}",
  },
  {
    name: "empty array",
    input: [],
    expected: "[]",
  },
  {
    name: "key sort",
    input: { b: 1, a: 2, c: 3 },
    expected: '{"a":2,"b":1,"c":3}',
  },
  {
    name: "nested + null",
    input: { a: { y: 2, x: 1 }, b: null },
    expected: '{"a":{"x":1,"y":2},"b":null}',
  },
  {
    name: "array of objects, keys sorted within",
    input: [{ b: 2, a: 1 }, { d: 4, c: 3 }],
    expected: '[{"a":1,"b":2},{"c":3,"d":4}]',
  },
  {
    name: "ar.trusted_issuers.v1-shaped doc",
    input: {
      sig: null,
      version: 1,
      kind: "ar.trusted_issuers.v1",
      issued_at: "2026-05-19T00:00:00Z",
      valid_until: "2026-06-19T00:00:00Z",
      publisher: "did:web:dekimu.com",
      publisher_key: "ed25519:abc",
      previous_sha256: null,
      issuers: [
        {
          notes: null,
          iss: "did:web:test.example",
          added_at: "2026-05-01T00:00:00Z",
          revoked_at: null,
          families: ["apr"],
          profiles_pinned: null,
        },
      ],
    },
    expected:
      '{"issued_at":"2026-05-19T00:00:00Z","issuers":[{"added_at":"2026-05-01T00:00:00Z","families":["apr"],"iss":"did:web:test.example","notes":null,"profiles_pinned":null,"revoked_at":null}],"kind":"ar.trusted_issuers.v1","previous_sha256":null,"publisher":"did:web:dekimu.com","publisher_key":"ed25519:abc","sig":null,"valid_until":"2026-06-19T00:00:00Z","version":1}',
  },
];

let failures = 0;
for (const { name, input, expected } of cases) {
  const got = canonicalize(input);
  if (got !== expected) {
    failures++;
    process.stderr.write(`FAIL: ${name}\n  expected: ${expected}\n  got:      ${got}\n`);
  } else {
    process.stdout.write(`ok ${name}\n`);
  }
}

const failsToThrow = [
  { name: "NaN", input: { n: NaN } },
  { name: "Infinity", input: { n: Infinity } },
  { name: "undefined value", input: { u: undefined } },
];
for (const { name, input } of failsToThrow) {
  try {
    canonicalize(input);
    failures++;
    process.stderr.write(`FAIL: ${name} should have thrown\n`);
  } catch {
    process.stdout.write(`ok throws on ${name}\n`);
  }
}

process.exit(failures === 0 ? 0 : 1);
