#!/usr/bin/env node
/**
 * Re-sign the head of the trusted-issuers chain.
 *
 * Invoked by `.github/workflows/monthly-republish.yml`. The workflow — not
 * this script — branches, commits and opens the PR.
 *
 * GOVERNANCE (2026-10-19): a merged PR in this PUBLIC repo is never the
 * approval for changing who is trusted. Two actions, two triggers:
 *
 *   renew          head is validly signed and needs a fresh window. The new
 *                  doc is built FROM THE SIGNED HEAD ITSELF — same issuer set,
 *                  next version, fresh issued_at/valid_until. Allowed from the
 *                  weekly cron and from workflow_dispatch.
 *   sign-proposal  head is unsigned or its sig does not verify (a merged
 *                  monitor revocation, an issuer addition, any edit). Allowed
 *                  ONLY from workflow_dispatch with `PROPOSAL_SHA256` equal to
 *                  the sha256 (hex) of the proposal file's committed bytes.
 *                  The founder's dispatch naming that hash IS the approval;
 *                  the script signs exactly the issuer set parsed from those
 *                  bytes. On cron it goes red ("content change awaits founder
 *                  dispatch") and signs nothing.
 *
 * Why weekly + a renewal margin: the old monthly cron skipped heads younger
 * than 30 days while every doc is valid for 30 days, so v01 (issued
 * 2026-07-17) expired 2026-08-16 — behind a dry-run gate that was never
 * opened, printing green every month.
 *
 * Env: TRIGGER (`schedule` | `workflow_dispatch`, from github.event_name;
 * unset = schedule, the conservative reading) · PROPOSAL_SHA256 ·
 * SIGNING_KEY_BASE64 (raw 32-byte Ed25519 seed; its pubkey MUST equal
 * publisher_key) · REPUBLISH_DISABLED=1 kill switch.
 *
 * Writes the new doc + `chain/head.json` (byte copy — the path
 * verify.dekimu.com serves) and deletes the signed proposal file; prints
 * `wrote=` / `version=` / `deleted=` to $GITHUB_OUTPUT.
 *
 * Exit: 0 = nothing due, or wrote a doc · 1 = error · 2 = action due but
 * refused or impossible (red on purpose — a silent dry-run is how v01 died).
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

export function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

/**
 * Trigger gate. `p` = plan(); returns { ok: true } or { ok: false, code, reason }.
 * `proposalSha` = the founder-supplied hash; `p.proposalSha256` = the committed bytes' hash.
 */
export function authorize(p, { trigger, proposalSha }) {
  const isDispatch = trigger === "workflow_dispatch";
  const named = (proposalSha ?? "").trim().toLowerCase();
  if (p.action === "sign-proposal") {
    if (!isDispatch) {
      return { ok: false, code: 2, reason: `content change awaits founder dispatch: ${p.proposalFile} (sha256 ${p.proposalSha256}) — run with -f proposal_sha256=<hex>` };
    }
    if (named === "") {
      return { ok: false, code: 2, reason: `proposal ${p.proposalFile} needs proposal_sha256 (committed bytes: ${p.proposalSha256})` };
    }
    if (named !== p.proposalSha256) {
      return { ok: false, code: 2, reason: `proposal_sha256 ${named} does not match ${p.proposalFile} as committed (${p.proposalSha256}) — signing nothing` };
    }
    return { ok: true };
  }
  if (named !== "") {
    return { ok: false, code: 2, reason: `proposal_sha256 given but there is no unsigned proposal to sign (plan: ${p.action}) — signing nothing` };
  }
  return { ok: true };
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
      proposalSha256: head.sha256,
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
  if (canonicalize(signed.issuers) !== canonicalize(base.issuers)) throw new Error("issuer set changed while signing — refusing");
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
    const bytes = await readFile(path.join(chainDir, file));
    entries.push({ file, version: Number.parseInt(m[1], 10), sha256: sha256Hex(bytes), doc: JSON.parse(bytes.toString("utf8")) });
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

  const auth = authorize(p, { trigger: process.env.TRIGGER ?? "schedule", proposalSha: process.env.PROPOSAL_SHA256 });
  if (!auth.ok) {
    process.stdout.write(`::error::${auth.reason}\n`);
    return auth.code;
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
    const deleted = p.action === "sign-proposal" ? p.proposalFile : "";
    await appendFile(process.env.GITHUB_OUTPUT, `wrote=${nextFile}\nversion=${next.version}\naction=${p.action}\ndeleted=${deleted}\n`);
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
