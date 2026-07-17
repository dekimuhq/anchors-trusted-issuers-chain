#!/usr/bin/env node
/**
 * Phase B6 founder ceremony — mint the bootstrap publisher key and sign the
 * GENESIS `ar.trusted_issuers.v1` list.
 *
 * Prepared 2026-07-16 for the autonomy-receipts go-live (checklist item 4,
 * knowledge/autonomy-tiers.md § Automation batch in the dekimu monorepo):
 * the genesis list admits `did:web:dekimu.com:autonomy` with
 * `families: ["action"]` so autonomy CI receipts (kid `autonomy-2026-07`)
 * stop rendering untrusted.
 *
 * Modes:
 *   node scripts/genesis.mjs              → dry-run: print the unsigned genesis doc, exit 0.
 *   node scripts/genesis.mjs --mint       → FOUNDER ONLY, full ceremony:
 *     1. Generate a fresh Ed25519 keypair in-process (node:crypto).
 *     2. Build + sign the genesis doc (sig over JCS canonical with sig:null,
 *        same convention as republish.mjs / ar.continuity.v1).
 *     3. Self-verify the signature before writing anything.
 *     4. Write chain/dekimu-trusted-issuers.v01.<issued_at>.json.
 *     5. Pipe the raw 32-byte seed (base64) straight into
 *        `gh secret set SIGNING_KEY_BASE64 -R dekimuhq/anchors-trusted-issuers-chain`
 *        via stdin — the seed is NEVER printed, logged, or written to disk.
 *        (No-escrow pattern: same as AUTONOMY_ANCHOR_KEY. Loss = re-mint +
 *        publisher-key rotation per README governance.)
 *     6. Print ONLY the public key + follow-up commands.
 *
 *   SIGNING_KEY_BASE64=<b64 seed> node scripts/genesis.mjs --sign
 *     → sign with a pre-existing seed instead of minting one (skips step 1+5).
 *
 * Refuses to run --mint/--sign when chain/ already has a genesis.
 */

import { readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { canonicalize } from "./lib/canonical.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");
const CHAIN_DIR = path.join(REPO_ROOT, "chain");
const CHAIN_REPO = "dekimuhq/anchors-trusted-issuers-chain";
const VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;

function log(msg) {
  process.stdout.write(`[genesis] ${msg}\n`);
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Genesis issuer set — the autonomy agent only. Further issuers land as v02+ per README governance. */
function genesisIssuers(nowIso) {
  return [
    {
      iss: "did:web:dekimu.com:autonomy",
      added_at: nowIso,
      revoked_at: null,
      families: ["action"],
      profiles_pinned: null,
      notes:
        "Dekimu autonomy agent (GitHub Actions CI lanes) — mints ar.action.v1 receipts " +
        "under kid autonomy-2026-07, pubkey ed25519:Gor-OBUqsaQ2_7dmEMXXQHPTtgdYm25kHFSnW42t5_I. " +
        "Contact: hello@dekimu.com.",
    },
  ];
}

function buildUnsignedGenesis(now, publisherKeyB64u) {
  const nowIso = now.toISOString();
  return {
    kind: "ar.trusted_issuers.v1",
    version: 1,
    issued_at: nowIso,
    valid_until: new Date(now.getTime() + VALIDITY_MS).toISOString(),
    publisher: "did:web:dekimu.com",
    publisher_key: `ed25519:${publisherKeyB64u}`,
    previous_sha256: null,
    issuers: genesisIssuers(nowIso),
    sig: null,
  };
}

async function chainIsEmpty() {
  let entries;
  try {
    entries = await readdir(CHAIN_DIR);
  } catch (err) {
    if (err && err.code === "ENOENT") return true;
    throw err;
  }
  return !entries.some((f) => /^dekimu-trusted-issuers\.v\d+\..+\.json$/.test(f));
}

/** Wrap a raw 32-byte Ed25519 seed as a node:crypto private key (RFC 8410 PKCS8). */
function signerFromSeed(seed) {
  if (seed.length !== 32) throw new Error(`seed must be 32 bytes, got ${seed.length}`);
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: "der", type: "pkcs8" });
}

function rawPublicKey(signerKey) {
  const spki = crypto.createPublicKey(signerKey).export({ format: "der", type: "spki" });
  return new Uint8Array(spki.subarray(spki.length - 32)); // raw key = last 32 bytes of Ed25519 SPKI
}

function setGhSecret(name, value) {
  const res = spawnSync("gh", ["secret", "set", name, "-R", CHAIN_REPO], {
    input: value,
    stdio: ["pipe", "inherit", "inherit"],
  });
  if (res.status !== 0) throw new Error(`gh secret set ${name} failed (exit ${res.status})`);
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const mint = args.has("--mint");
  const signExisting = args.has("--sign");
  const now = new Date();

  if (!mint && !signExisting) {
    log("dry-run — unsigned genesis doc (publisher_key placeholder):");
    process.stdout.write(JSON.stringify(buildUnsignedGenesis(now, "PLACEHOLDER_B6_PENDING"), null, 2) + "\n");
    log("run with --mint (founder ceremony) or SIGNING_KEY_BASE64=… --sign to produce the signed genesis");
    return 0;
  }

  if (!(await chainIsEmpty())) {
    throw new Error("chain/ already contains a genesis — this script only mints v01. Use republish.mjs for v<N+1>.");
  }

  let seed;
  if (signExisting) {
    const b64 = process.env.SIGNING_KEY_BASE64;
    if (!b64) throw new Error("--sign requires SIGNING_KEY_BASE64 env (base64 of raw 32-byte Ed25519 seed)");
    seed = Buffer.from(b64, "base64");
  } else {
    seed = crypto.randomBytes(32);
  }

  const signerKey = signerFromSeed(seed);
  const pubB64u = base64UrlEncode(rawPublicKey(signerKey));

  const unsigned = buildUnsignedGenesis(now, pubB64u);
  const sig = crypto.sign(null, Buffer.from(canonicalize(unsigned)), signerKey);
  const signed = { ...unsigned, sig: base64UrlEncode(sig) };

  // Self-verify before writing — a genesis that doesn't verify must never land.
  const verifyOk = crypto.verify(
    null,
    Buffer.from(canonicalize({ ...signed, sig: null })),
    crypto.createPublicKey(signerKey),
    sig,
  );
  if (!verifyOk) throw new Error("self-verify failed — refusing to write genesis");

  const filename = `dekimu-trusted-issuers.v01.${signed.issued_at}.json`;
  await writeFile(path.join(CHAIN_DIR, filename), JSON.stringify(signed, null, 2) + "\n");
  log(`wrote chain/${filename}`);

  if (mint) {
    // Seed goes straight into the repo secret — never displayed (no-escrow pattern).
    setGhSecret("SIGNING_KEY_BASE64", seed.toString("base64"));
    log("SIGNING_KEY_BASE64 set on the chain repo (seed exists ONLY there — loss = re-mint + key rotation)");
  }

  log(`bootstrap publisher public key: ed25519:${pubB64u}`);
  log("follow-ups (in order):");
  log(`  1. git add chain/${filename} && git commit -m 'feat(chain): genesis v01 — autonomy issuer (families: action)' && git push`);
  log("  2. anchors monorepo: set BOOTSTRAP_PUBLISHER_KEY in trusted-issuers/src/bootstrap.ts to the pubkey above (MAJOR bump per governance)");
  log("  3. verify.dekimu.com: add autonomy kid to CLAIMS_VERIFY_KEYS_JSON to flip valid_untrusted → valid_trusted:");
  log('     "autonomy-2026-07": { "issuer": "did:web:dekimu.com:autonomy", "publicKey": "Gor-OBUqsaQ2_7dmEMXXQHPTtgdYm25kHFSnW42t5_I" }');
  log("  4. optional: enable the monthly republish (gh secret set REPUBLISH_ENABLED -R " + CHAIN_REPO + " --body 1)");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`[genesis] ERROR: ${err?.message ?? err}\n`);
    process.exit(1);
  },
);
