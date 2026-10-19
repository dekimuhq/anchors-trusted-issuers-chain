#!/usr/bin/env node
/**
 * Re-sign the head of the trusted-issuers chain before it expires.
 *
 * Invoked by `.github/workflows/monthly-republish.yml` (weekly check). The
 * workflow — not this script — branches, commits and opens the PR.
 *
 * Why weekly + a renewal margin (2026-10-19): the old monthly cron skipped a
 * head younger than 30 days while every doc is only valid for 30 days, so a
 * doc issued mid-month was guaranteed to sit expired for up to a month. v01
 * (issued 2026-07-17, valid_until 2026-08-16) expired that way — and then the
 * job stayed dry-run because `REPUBLISH_ENABLED` was never provisioned at the
 * B6 ceremony, printing a green "would build v02" every month.
 *
 * Logic:
 *   1. Read every `chain/dekimu-trusted-issuers.vNN.*.json`.
 *   2. `lastSigned` = highest-version doc whose `sig` verifies under its own
 *      `publisher_key`. `head` = highest-version doc overall.
 *   3. head unsigned / sig invalid → it is a merged governance proposal (the
 *      daily monitor writes revocations with `sig: null`; issuer additions are
 *      PR edits). Sign it as `lastSigned.version + 1`, chained to `lastSigned`,
 *      and delete the proposal file.
 *   4. head signed and `valid_until - now >= RENEW_MARGIN_MS` → fresh, exit 0.
 *   5. Otherwise build `head.version + 1` with a fresh 30-day window.
 *   6. Signing key = `SIGNING_KEY_BASE64` (raw 32-byte Ed25519 seed). Its
 *      public key MUST equal the doc's `publisher_key`, else refuse.
 *   7. Write the new file + `chain/head.json` (byte copy of the newest signed
 *      doc — the stable path verify.dekimu.com fetches), print
 *      `wrote=<filename>` to $GITHUB_OUTPUT.
 *
 * Exit codes: 0 = fresh or wrote a doc · 1 = error · 2 = a renewal was due but
 * could not be produced (no key / kill switch) — red on purpose, because a
 * silent dry-run is exactly how v01 expired unnoticed.
 *
 * Kill switch: `REPUBLISH_DISABLED=1` (repo variable) → no write, exit 2 when
 * a renewal was due.
 */

import { readdir, readFile, writeFile, unlink, appendFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import { canonicalize } from "./lib/canonical.mjs";

export const VALIDITY_MS = 30 * 24 * 60 * 60 * 1000;
export const RENEW_MARGIN_MS = 14 * 24 * 60 * 60 * 1000;
const FILE_RE = /^dekimu-trusted-issuers\.v(\d+)\..+\.json$/;
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function log(msg) {
  process.stdout.write(`[republish] ${msg}\n`);
}

export function base64UrlEncode(bytes) {
  return Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function sha256OfCanonical(doc) {
  return `sha256:${crypto.createHash("sha256").update(canonicalize(doc)).digest("hex")}`;
}

export function signerFromSeedB64(b64) {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) {
    throw new Error(`SIGNING_KEY_BASE64 decodes to ${raw.length} bytes; expected 32 (raw Ed25519 seed)`);
  }
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, raw]), format: "der", type: "pkcs8" });
}

export function publisherKeyOf(privateKey) {
  const spki = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return `ed25519:${base64UrlEncode(spki.subarray(spki.length - 32))}`;
}

/** True iff `doc.sig` verifies over JCS({...doc, sig:null}) under `doc.publisher_key`. */
export function sigValid(doc) {
  if (typeof doc?.sig !== "string" || typeof doc?.publisher_key !== "string") return false;
  if (!doc.publisher_key.startsWith("ed25519:")) return false;
  try {
    const raw = Buffer.from(doc.publisher_key.slice("ed25519:".length), "base64url");
    if (raw.length !== 32) return false;
    const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
    return crypto.verify(null, Buffer.from(canonicalize({ ...doc, sig: null })), pub, Buffer.from(doc.sig, "base64url"));
  } catch {
    return false;
  }
}

/**
 * Pure planner. `entries` = [{ file, doc }] sorted by version ascending.
 * Returns { action: "none"|"empty"|"renew"|"sign-proposal", base?, prev?, proposalFile?, reason }.
 */
export function plan(entries, now) {
  if (entries.length === 0) return { action: "empty", reason: "chain/ is empty" };
  const head = entries.at(-1);
  const lastSigned = [...entries].reverse().find((e) => sigValid(e.doc)) ?? null;
  if (!sigValid(head.doc)) {
    if (lastSigned === null) return { action: "error", reason: "no validly signed doc in chain/ to chain a proposal onto" };
    return {
      action: "sign-proposal",
      base: head.doc,
      prev: lastSigned.doc,
      proposalFile: head.file,
      reason: `head ${head.file} is unsigned or its sig does not verify — signing it as v${lastSigned.doc.version + 1}`,
    };
  }
  const remainingMs = Date.parse(head.doc.valid_until) - now.getTime();
  if (remainingMs >= RENEW_MARGIN_MS) {
    return { action: "none", reason: `head v${head.doc.version} valid for ${(remainingMs / 86400000).toFixed(1)} more days` };
  }
  return {
    action: "renew",
    base: head.doc,
    prev: head.doc,
    reason: remainingMs < 0
      ? `head v${head.doc.version} EXPIRED ${(-remainingMs / 86400000).toFixed(1)} days ago`
      : `head v${head.doc.version} expires in ${(remainingMs / 86400000).toFixed(1)} days (< ${RENEW_MARGIN_MS / 86400000}d margin)`,
  };
}

/** Build + sign the next doc. `prev` is the signed predecessor it chains onto. */
export function buildNext({ base, prev, now, privateKey }) {
  const signerKey = publisherKeyOf(privateKey);
  if (signerKey !== prev.publisher_key || signerKey !== base.publisher_key) {
    throw new Error(`signing key ${signerKey} does not match publisher_key ${prev.publisher_key} — refusing (key rotation is a founder ceremony)`);
  }
  const unsigned = {
    ...base,
    version: prev.version + 1,
    issued_at: now.toISOString(),
    valid_until: new Date(now.getTime() + VALIDITY_MS).toISOString(),
    previous_sha256: sha256OfCanonical(prev),
    sig: null,
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(unsigned)), privateKey);
  const signed = { ...unsigned, sig: base64UrlEncode(sig) };
  if (!sigValid(signed)) throw new Error("self-verify of the new doc failed");
  return signed;
}

export function fileNameFor(doc) {
  return `dekimu-trusted-issuers.v${String(doc.version).padStart(2, "0")}.${doc.issued_at}.json`;
}

export async function loadChain(chainDir) {
  let names;
  try {
    names = await readdir(chainDir);
  } catch (err) {
    if (err?.code === "ENOENT") return [];
    throw err;
  }
  const entries = [];
  for (const file of names) {
    const m = file.match(FILE_RE);
    if (!m) continue;
    entries.push({ file, version: Number.parseInt(m[1], 10), doc: JSON.parse(await readFile(path.join(chainDir, file), "utf8")) });
  }
  return entries.sort((a, b) => a.version - b.version);
}

async function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const chainDir = path.join(repoRoot, "chain");
  const now = new Date();
  log(`now: ${now.toISOString()}`);

  const entries = await loadChain(chainDir);
  const p = plan(entries, now);
  log(p.reason);
  if (p.action === "empty" || p.action === "none") return 0;
  if (p.action === "error") {
    process.stderr.write(`[republish] ERROR: ${p.reason}\n`);
    return 1;
  }

  if (process.env.REPUBLISH_DISABLED === "1") {
    process.stdout.write(`::error::renewal due (${p.reason}) but REPUBLISH_DISABLED=1 — chain head will expire\n`);
    return 2;
  }
  const b64 = process.env.SIGNING_KEY_BASE64;
  if (!b64) {
    process.stdout.write(`::error::renewal due (${p.reason}) but SIGNING_KEY_BASE64 is not available to this run\n`);
    return 2;
  }

  const next = buildNext({ base: p.base, prev: p.prev, now, privateKey: signerFromSeedB64(b64) });
  const nextFile = fileNameFor(next);
  const body = JSON.stringify(next, null, 2) + "\n";
  await writeFile(path.join(chainDir, nextFile), body);
  await writeFile(path.join(chainDir, "head.json"), body);
  if (p.action === "sign-proposal") await unlink(path.join(chainDir, p.proposalFile));
  log(`wrote ${nextFile} (previous_sha256 ${next.previous_sha256}) + head.json`);
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `wrote=${nextFile}\nversion=${next.version}\n`);
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`[republish] ERROR: ${err?.message ?? err}\n`);
      process.exit(1);
    },
  );
}
