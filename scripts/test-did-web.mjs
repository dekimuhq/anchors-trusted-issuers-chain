#!/usr/bin/env node
/**
 * Pins `scripts/lib/did-web.mjs` to the resolver's derivation.
 * Run with `node scripts/test-did-web.mjs`. Exits 1 on any divergence.
 *
 * The vectors below are copied from the docblock of `didWebToUrl()` in
 * `@dekimuhq/did-web-resolver`. If that function changes, this file must
 * change with it — the monitor probing a different URL than the verifier
 * resolves is what caused the 2026-07-20 false revocation cascade.
 */

import { baseUrlOf, issuerSlug } from "./lib/did-web.mjs";

let failures = 0;
const check = (name, actual, expected) => {
  if (actual === expected) return;
  failures++;
  process.stderr.write(`FAIL ${name}\n  expected: ${expected}\n  actual:   ${actual}\n`);
};

const KEY_DOC = "/.well-known/dekimu-keys.json";

// --- resolver parity vectors (verbatim from didWebToUrl's docblock) --------
check(
  "apex domain",
  baseUrlOf("did:web:example.com") + KEY_DOC,
  "https://example.com/.well-known/dekimu-keys.json",
);
check(
  "nested path segments",
  baseUrlOf("did:web:example.com:user:alice") + KEY_DOC,
  "https://example.com/user/alice/.well-known/dekimu-keys.json",
);
check(
  "percent-decoded segment",
  baseUrlOf("did:web:example.com:org%3A42") + KEY_DOC,
  "https://example.com/org:42/.well-known/dekimu-keys.json",
);

// --- the live issuer this repo actually governs ---------------------------
// Regression: this returned https://dekimu.com (apex) before 2026-07-22,
// which is not where the verifier looks.
check(
  "dekimu autonomy issuer",
  baseUrlOf("did:web:dekimu.com:autonomy") + KEY_DOC,
  "https://dekimu.com/autonomy/.well-known/dekimu-keys.json",
);

// --- slug: two issuers on one domain must not collide ---------------------
check("slug apex", issuerSlug("did:web:dekimu.com"), "dekimu.com");
check("slug path", issuerSlug("did:web:dekimu.com:autonomy"), "dekimu.com_autonomy");
if (issuerSlug("did:web:dekimu.com") === issuerSlug("did:web:dekimu.com:autonomy")) {
  failures++;
  process.stderr.write("FAIL slug collision: apex and path issuer share a branch name\n");
}

// --- rejects non-did:web ---------------------------------------------------
for (const bad of ["https://dekimu.com", "did:key:z6Mk", "", "did:web:"]) {
  let threw = false;
  try {
    baseUrlOf(bad);
  } catch {
    threw = true;
  }
  if (!threw) {
    failures++;
    process.stderr.write(`FAIL did not reject: ${JSON.stringify(bad)}\n`);
  }
}

if (failures > 0) {
  process.stderr.write(`\n${failures} failure(s)\n`);
  process.exit(1);
}
process.stdout.write("[test-did-web] all cases green\n");
