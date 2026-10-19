#!/usr/bin/env node
/**
 * Republish planner/signer checks. `node scripts/test-republish.mjs`, exit 1 on failure.
 * Uses a throwaway key — never the real publisher seed.
 */
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "./lib/canonical.mjs";
import { mkdtempSync, mkdirSync, cpSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import {
  plan, buildNext, sigValid, sha256OfCanonical, publisherKeyOf, base64UrlEncode, loadChain, authorize, sha256Hex,
  VALIDITY_MS, RENEW_MARGIN_MS,
} from "./republish.mjs";

let failed = 0;
function check(name, cond) {
  process.stdout.write(`${cond ? "ok  " : "FAIL"} ${name}\n`);
  if (!cond) failed++;
}

const DAY = 86400000;
const { privateKey } = crypto.generateKeyPairSync("ed25519");
const pk = publisherKeyOf(privateKey);
function signDoc(doc) {
  const unsigned = { ...doc, sig: null };
  return { ...unsigned, sig: base64UrlEncode(crypto.sign(null, Buffer.from(canonicalize(unsigned)), privateKey)) };
}
const t0 = new Date("2026-07-17T00:00:00.000Z");
const genesis = signDoc({
  kind: "ar.trusted_issuers.v1", version: 1, issued_at: t0.toISOString(),
  valid_until: new Date(t0.getTime() + VALIDITY_MS).toISOString(),
  publisher: "did:web:test.example", publisher_key: pk, previous_sha256: null,
  issuers: [{ iss: "did:web:a.example", added_at: t0.toISOString(), revoked_at: null, families: ["action"], profiles_pinned: null, notes: null }],
});
const e = (doc) => ({ file: `dekimu-trusted-issuers.v${String(doc.version).padStart(2, "0")}.${doc.issued_at}.json`, doc });

check("genesis signature verifies", sigValid(genesis));
check("fresh head → none", plan([e(genesis)], new Date(t0.getTime() + 5 * DAY)).action === "none");
check("inside renewal margin → renew", plan([e(genesis)], new Date(t0.getTime() + VALIDITY_MS - RENEW_MARGIN_MS + DAY)).action === "renew");
const late = new Date(t0.getTime() + 94 * DAY);
const p = plan([e(genesis)], late);
check("expired head → renew", p.action === "renew" && /EXPIRED/.test(p.reason));
const v2 = buildNext({ base: p.base, prev: p.prev, now: late, privateKey });
check("v2 version = 2", v2.version === 2);
check("v2 signature verifies", sigValid(v2));
check("v2 previous_sha256 = sha256(canonical(signed v1))", v2.previous_sha256 === sha256OfCanonical(genesis));
check("v2 window is now..now+30d", v2.issued_at === late.toISOString() && Date.parse(v2.valid_until) - late.getTime() === VALIDITY_MS);
check("v2 keeps issuers", JSON.stringify(v2.issuers) === JSON.stringify(genesis.issuers));
check("v2 fresh right after → none", plan([e(genesis), e(v2)], late).action === "none");

// monitor-style proposal: unsigned, revoked_at set, previous_sha256 null
const proposal = { ...v2, version: 3, issuers: [{ ...v2.issuers[0], revoked_at: late.toISOString() }], previous_sha256: null, sig: null };
const pp = plan([e(genesis), e(v2), e(proposal)], late);
check("unsigned head → sign-proposal chained to v2", pp.action === "sign-proposal" && pp.prev.version === 2);
const v3 = buildNext({ base: pp.base, prev: pp.prev, now: late, privateKey });
check("v3 chains to v2 and carries the revocation", v3.previous_sha256 === sha256OfCanonical(v2) && v3.issuers[0].revoked_at !== null && sigValid(v3));

const tampered = { ...v2, issuers: [] };
check("edited-but-not-re-signed head → sign-proposal", plan([e(genesis), e(tampered)], late).action === "sign-proposal");

const { privateKey: other } = crypto.generateKeyPairSync("ed25519");
let threw = false;
try { buildNext({ base: genesis, prev: genesis, now: late, privateKey: other }); } catch { threw = true; }
check("wrong signing key refused", threw);

// ---- trigger gate (pure) ----
const renewPlan = plan([e(genesis)], late);
check("cron may renew", authorize(renewPlan, { trigger: "schedule" }).ok);
check("dispatch may renew", authorize(renewPlan, { trigger: "workflow_dispatch" }).ok);
check("renew + stray proposal_sha256 → refused", !authorize(renewPlan, { trigger: "workflow_dispatch", proposalSha: "ab" }).ok);
const propPlan = { ...pp, proposalSha256: "a".repeat(64) };
const cronProp = authorize(propPlan, { trigger: "schedule" });
check("cron + proposal → red, 'content change awaits founder dispatch'", !cronProp.ok && cronProp.code === 2 && /content change awaits founder dispatch/.test(cronProp.reason));
check("unset trigger treated as cron", !authorize(propPlan, {}).ok);
check("dispatch + proposal, no hash → red", !authorize(propPlan, { trigger: "workflow_dispatch" }).ok);
check("dispatch + wrong hash → red", !authorize(propPlan, { trigger: "workflow_dispatch", proposalSha: "b".repeat(64) }).ok);
check("dispatch + right hash (case-insensitive) → ok", authorize(propPlan, { trigger: "workflow_dispatch", proposalSha: "A".repeat(64) }).ok);

// ---- end-to-end: the real script in a throwaway repo copy ----
const here = path.dirname(fileURLToPath(import.meta.url));
const seedB64 = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("base64");
function sandbox() {
  const dir = mkdtempSync(path.join(tmpdir(), "republish-e2e-"));
  cpSync(here, path.join(dir, "scripts"), { recursive: true });
  mkdirSync(path.join(dir, "chain"));
  const fresh = new Date();
  const g = signDoc({ ...genesis, issued_at: new Date(fresh.getTime() - DAY).toISOString(), valid_until: new Date(fresh.getTime() + 29 * DAY).toISOString() });
  writeFileSync(path.join(dir, "chain", e(g).file), JSON.stringify(g, null, 2) + "\n");
  writeFileSync(path.join(dir, "chain", "head.json"), JSON.stringify(g, null, 2) + "\n");
  const prop = { ...g, version: 2, issued_at: fresh.toISOString(), issuers: [{ ...g.issuers[0], revoked_at: fresh.toISOString() }], previous_sha256: null, sig: null };
  const propFile = e(prop).file;
  const propBytes = Buffer.from(JSON.stringify(prop, null, 2) + "\n");
  writeFileSync(path.join(dir, "chain", propFile), propBytes);
  return { dir, g, propFile, propSha: sha256Hex(propBytes) };
}
function run(dir, env) {
  return spawnSync(process.execPath, [path.join(dir, "scripts", "republish.mjs")], {
    env: { PATH: process.env.PATH, SIGNING_KEY_BASE64: seedB64, ...env }, encoding: "utf8",
  });
}
const files = (dir) => readdirSync(path.join(dir, "chain")).sort().join(",");
{
  const sb = sandbox(); const before = files(sb.dir);
  const r = run(sb.dir, { TRIGGER: "schedule" });
  check("e2e cron + proposal → exit 2, says awaits founder dispatch", r.status === 2 && /content change awaits founder dispatch/.test(r.stdout));
  check("e2e cron + proposal → nothing written", files(sb.dir) === before);
}
{
  const sb = sandbox(); const before = files(sb.dir);
  const r = run(sb.dir, { TRIGGER: "workflow_dispatch", PROPOSAL_SHA256: "0".repeat(64) });
  check("e2e dispatch + wrong hash → exit 2, nothing written", r.status === 2 && files(sb.dir) === before);
}
{
  const sb = sandbox();
  const r = run(sb.dir, { TRIGGER: "workflow_dispatch", PROPOSAL_SHA256: sb.propSha, REPUBLISH_DISABLED: "1" });
  check("e2e right hash but kill switch → exit 2", r.status === 2);
}
{
  const sb = sandbox();
  const r = run(sb.dir, { TRIGGER: "workflow_dispatch", PROPOSAL_SHA256: sb.propSha });
  const after = await loadChain(path.join(sb.dir, "chain"));
  const head = JSON.parse(readFileSync(path.join(sb.dir, "chain", "head.json"), "utf8"));
  check("e2e dispatch + right hash → exit 0, signs v2", r.status === 0 && after.length === 2 && after[1].doc.version === 2 && sigValid(after[1].doc));
  check("e2e signed v2 chains to v1 and carries exactly the proposal's issuers", after[1].doc.previous_sha256 === sha256OfCanonical(after[0].doc) && after[1].doc.issuers[0].revoked_at !== null && after[1].doc.issuers.length === 1);
  check("e2e proposal file removed, head.json = v2", !files(sb.dir).includes(sb.propFile) && JSON.stringify(head) === JSON.stringify(after[1].doc));
}

// the real committed chain must verify under its own publisher_key. A merged
// governance proposal (unsigned head, e.g. a monitor revocation) is tolerated —
// signing it is exactly what republish does next.
const chainDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "chain");
const all = await loadChain(chainDir);
const real = all.length > 0 && all.at(-1).doc.sig === null ? all.slice(0, -1) : all;
check(`committed chain: ${real.length} signed doc(s), all signatures verify`, real.length > 0 && real.every((x) => sigValid(x.doc)));
check("committed chain starts at genesis", real.length > 0 && real[0].doc.previous_sha256 === null);
for (let i = 1; i < real.length; i++) {
  check(`committed chain link v${real[i].doc.version} -> v${real[i - 1].doc.version}`, real[i].doc.previous_sha256 === sha256OfCanonical(real[i - 1].doc) && real[i].doc.version === real[i - 1].doc.version + 1);
}
const { readFile } = await import("node:fs/promises");
const head = JSON.parse(await readFile(path.join(chainDir, "head.json"), "utf8"));
check("chain/head.json is the newest signed doc", JSON.stringify(head) === JSON.stringify(real.at(-1)?.doc));

process.exit(failed === 0 ? 0 : 1);
