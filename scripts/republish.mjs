#!/usr/bin/env node
/**
 * Monthly republish of the head trusted-issuers list.
 *
 * Invoked by `.github/workflows/monthly-republish.yml`.
 *
 * Dry-run is the default. The script ONLY mutates the working tree when both
 * of these are true:
 *   - `REPUBLISH_ENABLED=1` env var is set (gates accidental cron firings)
 *   - `SIGNING_KEY_BASE64` env var holds a 32-byte raw Ed25519 private key
 *
 * Neither is set until Phase B6 (founder ceremony — real bootstrap key). Until
 * then the workflow runs every month and prints what it would do without
 * touching the repo.
 *
 * Logic (per master plan §2.5 + Phase B4 plan):
 *   1. Read latest chain file (highest version) under `chain/`.
 *   2. If no chain file exists → exit 0 with "chain empty, nothing to republish"
 *      (initial state until B6 commits the genesis list).
 *   3. If `now() - issued_at < 30 days` → exit 0 with "head is fresh".
 *   4. Otherwise build the next-version doc:
 *        - same `kind`, `publisher`, `publisher_key`, `issuers`
 *        - `version` += 1
 *        - `issued_at` = now, `valid_until` = now + 30d
 *        - `previous_sha256` = `sha256:` + sha256(canonical(prev)) over SIGNED bytes
 *      Sign with the publisher key (read from `SIGNING_KEY_BASE64`), set
 *      `sig` to the base64url-encoded signature.
 *   5. If dry-run → print the new doc to stdout; exit 0.
 *   6. Otherwise write `chain/dekimu-trusted-issuers.v<NN>.<issued_at>.json`,
 *      git commit + push, then trigger the verify.dekimu.com rebuild workflow.
 *
 * The `verify.dekimu.com` rebuild hook is a forward-reference; this script
 * prints the trigger command but does not execute it until B6.
 */

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { canonicalize } from "./lib/canonical.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..");
const CHAIN_DIR = path.join(REPO_ROOT, "chain");
const REPUBLISH_INTERVAL_MS = 30 * 24 * 60 * 60 * 1000;
const RFC8032_RAW_PRIVATE_BYTES = 32;

function log(msg) {
  process.stdout.write(`[republish] ${msg}\n`);
}

async function listChainFiles() {
  let entries;
  try {
    entries = await readdir(CHAIN_DIR);
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
  return entries
    .filter((f) => /^dekimu-trusted-issuers\.v\d+\..+\.json$/.test(f))
    .sort();
}

function versionOf(filename) {
  const m = filename.match(/^dekimu-trusted-issuers\.v(\d+)\./);
  return m ? Number.parseInt(m[1], 10) : -1;
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256OfCanonical(doc) {
  const canonical = canonicalize(doc);
  const h = crypto.createHash("sha256");
  h.update(canonical);
  return `sha256:${h.digest("hex")}`;
}

function loadSigningKeyOrNull() {
  const b64 = process.env.SIGNING_KEY_BASE64;
  if (!b64) return null;
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== RFC8032_RAW_PRIVATE_BYTES) {
    throw new Error(
      `SIGNING_KEY_BASE64 decodes to ${raw.length} bytes; expected ${RFC8032_RAW_PRIVATE_BYTES} for raw Ed25519 private key`,
    );
  }
  // Wrap as PKCS8 for Node's `crypto.createPrivateKey`.
  // Ed25519 PKCS8 prefix per RFC 8410.
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8 = Buffer.concat([pkcs8Prefix, raw]);
  return crypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

async function main() {
  const dryRun = process.env.REPUBLISH_ENABLED !== "1";
  const now = new Date();

  log(`dry-run: ${dryRun}`);
  log(`now: ${now.toISOString()}`);

  const files = await listChainFiles();
  if (files.length === 0) {
    log("chain/ is empty — nothing to republish (genesis list ships in Phase B6)");
    return 0;
  }

  const head = files.sort((a, b) => versionOf(a) - versionOf(b)).at(-1);
  log(`head: ${head}`);
  const headDoc = JSON.parse(await readFile(path.join(CHAIN_DIR, head), "utf8"));

  const issuedAtMs = Date.parse(headDoc.issued_at);
  const ageMs = now.getTime() - issuedAtMs;
  log(`head age: ${(ageMs / 1000 / 60 / 60 / 24).toFixed(1)} days`);
  if (ageMs < REPUBLISH_INTERVAL_MS) {
    log("head is fresh (< 30d) — skipping republish");
    return 0;
  }

  const signingKey = loadSigningKeyOrNull();
  if (dryRun || !signingKey) {
    log(`would build v${headDoc.version + 1} signed by publisher key ${headDoc.publisher_key}`);
    log("dry-run / no signing key — exiting without writing");
    return 0;
  }

  const validUntilMs = now.getTime() + REPUBLISH_INTERVAL_MS;
  const nextUnsigned = {
    ...headDoc,
    version: headDoc.version + 1,
    issued_at: now.toISOString(),
    valid_until: new Date(validUntilMs).toISOString(),
    previous_sha256: sha256OfCanonical(headDoc),
    sig: null,
  };

  const sig = crypto.sign(null, Buffer.from(canonicalize(nextUnsigned)), signingKey);
  const nextSigned = { ...nextUnsigned, sig: base64UrlEncode(sig) };

  const nextFilename = `dekimu-trusted-issuers.v${String(nextSigned.version).padStart(2, "0")}.${nextSigned.issued_at}.json`;
  const nextPath = path.join(CHAIN_DIR, nextFilename);
  await writeFile(nextPath, JSON.stringify(nextSigned, null, 2) + "\n");
  log(`wrote ${nextFilename}`);
  log("next steps (gated on B6): git add + commit + push, then trigger verify.dekimu.com rebuild");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`[republish] ERROR: ${err?.message ?? err}\n`);
    process.exit(1);
  },
);
