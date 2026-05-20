#!/usr/bin/env node
/**
 * Daily allowlist domain-reachability monitor.
 *
 * Invoked by `.github/workflows/daily-monitor.yml`.
 *
 * For every active issuer (`revoked_at: null`) in the head chain file,
 * probes both `/.well-known/dekimu-keys.json` (Phase B — required) and
 * `/.well-known/dekimu-issuer.json` (Phase C manifest — 404 OK in v1).
 *
 * State persists in `.github/state/monitor.json` (committed). Per-issuer
 * consecutive-failure counters increment on any key-doc failure and reset on
 * success. When a counter hits the failure threshold (default 3), the monitor:
 *   1. Builds a proposed next-version chain file with `revoked_at: <now>` set
 *      on the unreachable issuer (sig: null — founder signs at merge time).
 *   2. Writes it to `chain/dekimu-trusted-issuers.v<NN>.<now>.json` on a
 *      branch named `revocation/<issuer-slug>-<date>`.
 *   3. The workflow opens a DRAFT PR for founder review. Merging is manual.
 *
 * Until Phase B6 commits the genesis list, `chain/` is empty and the monitor
 * exits with "chain empty, nothing to monitor".
 *
 * The script never signs anything. Re-signing happens via the monthly
 * republish cron (gated on `REPUBLISH_ENABLED=1` + `SIGNING_KEY_BASE64`)
 * after the founder merges the revocation PR.
 *
 * Logic (per master plan §2.5 + Q6, Phase B5 plan):
 *   1. Read latest chain file under `chain/`. Empty → exit 0.
 *   2. Load state from `.github/state/monitor.json`. Missing → empty map.
 *   3. For each issuer where `revoked_at === null`:
 *      a. Fetch `https://<domain>/.well-known/dekimu-keys.json` (required).
 *      b. Fetch `https://<domain>/.well-known/dekimu-issuer.json` (optional).
 *      c. (a) ok → reset counter to 0. (a) fail → increment counter.
 *   4. Persist state to `.github/state/monitor.json`.
 *   5. For any issuer with counter ≥ FAILURE_THRESHOLD: write proposed
 *      revocation chain file + emit `PROPOSED_REVOCATION_BRANCH` + ISSUER
 *      env vars for the workflow to consume.
 */

import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize } from "./lib/canonical.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..");
const CHAIN_DIR = path.join(REPO_ROOT, "chain");
const STATE_DIR = path.join(REPO_ROOT, ".github", "state");
const STATE_FILE = path.join(STATE_DIR, "monitor.json");

const FAILURE_THRESHOLD = 3;
const FETCH_TIMEOUT_MS = 10_000;
const KEY_DOC_PATH = "/.well-known/dekimu-keys.json";
const MANIFEST_PATH = "/.well-known/dekimu-issuer.json";

function log(msg) {
  process.stdout.write(`[monitor] ${msg}\n`);
}

function todayUtcIsoDate() {
  return new Date().toISOString().slice(0, 10);
}

function domainOf(iss) {
  if (!iss.startsWith("did:web:")) {
    throw new Error(`unsupported iss scheme: ${iss} (only did:web supported)`);
  }
  return iss.slice("did:web:".length).split(":")[0];
}

function issuerSlug(iss) {
  return domainOf(iss).replace(/[^a-z0-9.-]/gi, "_");
}

async function listChainFiles() {
  let entries;
  try {
    entries = await readdir(CHAIN_DIR);
  } catch (err) {
    if (err && err.code === "ENOENT") return [];
    throw err;
  }
  return entries.filter((f) => /^dekimu-trusted-issuers\.v\d+\..+\.json$/.test(f)).sort();
}

function versionOf(filename) {
  const m = filename.match(/^dekimu-trusted-issuers\.v(\d+)\./);
  return m ? Number.parseInt(m[1], 10) : -1;
}

async function loadState() {
  try {
    const raw = await readFile(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : { counters: {}, last_run: null };
  } catch (err) {
    if (err && err.code === "ENOENT") return { counters: {}, last_run: null };
    throw err;
  }
}

async function saveState(state) {
  await mkdir(STATE_DIR, { recursive: true });
  await writeFile(STATE_FILE, JSON.stringify(state, null, 2) + "\n");
}

async function probe(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
    return { ok: res.ok, status: res.status };
  } catch (err) {
    return { ok: false, status: 0, error: err?.message ?? String(err) };
  } finally {
    clearTimeout(t);
  }
}

function buildProposedRevocation(headDoc, targetIss, nowIso) {
  const issuers = headDoc.issuers.map((row) =>
    row.iss === targetIss && row.revoked_at === null
      ? { ...row, revoked_at: nowIso, revocation_reason: "domain_unreachable" }
      : row,
  );
  return {
    ...headDoc,
    version: headDoc.version + 1,
    issued_at: nowIso,
    valid_until: new Date(Date.parse(nowIso) + 30 * 24 * 60 * 60 * 1000).toISOString(),
    previous_sha256: null,
    issuers,
    sig: null,
  };
}

async function main() {
  const files = await listChainFiles();
  if (files.length === 0) {
    log("chain/ is empty — nothing to monitor (genesis list ships in Phase B6)");
    return 0;
  }

  const head = files.sort((a, b) => versionOf(a) - versionOf(b)).at(-1);
  log(`head: ${head}`);
  const headDoc = JSON.parse(await readFile(path.join(CHAIN_DIR, head), "utf8"));
  const state = await loadState();
  state.counters = state.counters && typeof state.counters === "object" ? state.counters : {};

  const nowIso = new Date().toISOString();
  state.last_run = nowIso;

  const proposedRevocations = [];
  for (const row of headDoc.issuers) {
    if (row.revoked_at !== null) continue;
    const domain = domainOf(row.iss);
    const keyRes = await probe(`https://${domain}${KEY_DOC_PATH}`);
    const manRes = await probe(`https://${domain}${MANIFEST_PATH}`);
    log(`${row.iss} key=${keyRes.status} manifest=${manRes.status}`);
    const prev = Number(state.counters[row.iss] ?? 0);
    if (keyRes.ok) {
      state.counters[row.iss] = 0;
    } else {
      state.counters[row.iss] = prev + 1;
      if (state.counters[row.iss] >= FAILURE_THRESHOLD) {
        proposedRevocations.push({ iss: row.iss, count: state.counters[row.iss] });
      }
    }
  }

  await saveState(state);
  log(`state saved (${Object.keys(state.counters).length} issuers tracked)`);

  if (proposedRevocations.length === 0) {
    log("no revocations to propose");
    return 0;
  }

  const target = proposedRevocations[0];
  log(`proposing revocation: ${target.iss} (${target.count} consecutive failures)`);
  const proposed = buildProposedRevocation(headDoc, target.iss, nowIso);
  const filename = `dekimu-trusted-issuers.v${String(proposed.version).padStart(2, "0")}.${nowIso}.json`;
  await writeFile(path.join(CHAIN_DIR, filename), JSON.stringify(proposed, null, 2) + "\n");
  log(`wrote ${filename} (sig: null — founder signs at merge)`);

  // Validate canonicalisation round-trips (defensive — catch malformed proposals before PR).
  canonicalize(proposed);

  const branch = `revocation/${issuerSlug(target.iss)}-${todayUtcIsoDate()}`;
  const ghOut = process.env.GITHUB_OUTPUT;
  if (ghOut) {
    await writeFile(
      ghOut,
      [
        `proposed=true`,
        `branch=${branch}`,
        `iss=${target.iss}`,
        `count=${target.count}`,
        `file=${filename}`,
      ].join("\n") + "\n",
      { flag: "a" },
    );
  }

  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`[monitor] ERROR: ${err?.message ?? err}\n`);
    process.exit(1);
  },
);
