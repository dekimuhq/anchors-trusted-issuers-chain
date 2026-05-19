# Security policy

This repository hosts the public, append-only hash chain of every published
`ar.trusted_issuers.v1` allowlist for the Anchored Receipts protocol family.
It is a passive mirror — the **operationally canonical** location is
`https://verify.dekimu.com/.well-known/dekimu-trusted-issuers.json`.

## Reporting a vulnerability

Email **security@dekimu.com** with subject `[anchors-trusted-issuers-chain]`.

In scope:

- Forged or tampered chain entries that the published verifier
  (`@dekimuhq/anchors-trusted-issuers`) accepts as valid.
- Discrepancies between this mirror and the canonical
  `verify.dekimu.com/.well-known/dekimu-trusted-issuers.json` head.
- Issuer DIDs in the head list whose `/.well-known/dekimu-keys.json` does not
  resolve, has been compromised, or whose published material is materially
  inaccurate.
- Bugs in `scripts/republish.mjs` or `scripts/lib/canonical.mjs` that produce
  JCS output diverging from the upstream `@dekimuhq/anchors-envelope`
  canonicalizer.
- Workflow security issues (`.github/workflows/*.yml`).

Out of scope:

- Issues in the verifier library itself — file those on
  `dekimuhq/dekimu` against `anchors/trusted-issuers/`.
- General CVEs in dependencies — open a PR with the upgrade instead.

## Response targets

- Acknowledge within 3 business days.
- Triage to confirmed / not-a-bug within 10 business days.
- Confirmed issues: coordinated disclosure window of 30 days unless a faster
  fix is required to prevent active exploitation.

## Threat model summary

- The chain repo is **passive**. A compromise of this repo cannot, on its own,
  cause a verifier to accept a malicious issuer — verifiers fetch and
  Ed25519-verify the head list against either a pinned bootstrap key OR a
  `did:web` resolver, both of which live outside this repo.
- A successful compromise here CAN make consumers see a stale list (rollback
  attack) until the next monthly re-sign or manual update. The daily monitor
  cron (Phase B5) is the detection layer for this.
- The bootstrap publisher key is **not** stored in this repo. The signing
  identity lives in the founder's 1Password vault and is loaded into GitHub
  Actions secrets only for the monthly republish workflow.

## Cryptographic primitives

- Ed25519 signatures (`node:crypto`).
- SHA-256 hash linkage between consecutive list versions.
- JCS (RFC 8785-lite) canonicalisation — `scripts/lib/canonical.mjs`.

No third-party crypto. No bundled keys. No live secrets in this repo.
