# anchors-trusted-issuers-chain

Append-only hash chain of every published `ar.trusted_issuers.v1` allowlist
for the [Anchored Receipts](https://github.com/dekimuhq) protocol family.

> **Operationally canonical:** `https://verify.dekimu.com/.well-known/dekimu-trusted-issuers.json`.
>
> This repo is a passive mirror. Verifiers MUST NOT fetch the head from this
> repo at runtime — fetch the canonical location and verify against either a
> pinned bootstrap key or a `did:web` resolver.

---

## What this is

The Anchored Receipts protocol family (APR, ACR, ARR, ALR, ANR, ASR, ABR, AIR,
and friends) uses a single shared allowlist of "trusted issuers" — DIDs whose
receipts a verifier is willing to surface as `valid_trusted` instead of
`valid_untrusted`. The wire-format of the allowlist is
[`ar.trusted_issuers.v1`](https://github.com/dekimuhq/dekimu/blob/main/anchors/meta/FAMILY-CONSISTENCY.md)
— a standalone signed JSON document, sibling-shape to `ar.continuity.v1`,
**not** wrapped in the v=2 envelope.

Each time the allowlist changes (new issuer added, existing issuer revoked,
key rotation) a new version is published, signed by the bootstrap publisher
key, and committed to this repo. Consecutive versions are linked via
`previous_sha256` = `sha256(canonical(previous-signed-doc))`. Verifiers
implementing the `@dekimuhq/anchors-trusted-issuers` library can replay the
chain from genesis to detect tampering at any link.

---

## Repository layout

```
chain/
  head.json                                      ← copy of the newest signed doc (served by verify.dekimu.com)
  dekimu-trusted-issuers.v01.<issued_at>.json    ← genesis (Phase B6)
  dekimu-trusted-issuers.v02.<issued_at>.json
  …
.github/workflows/
  monthly-republish.yml                          ← weekly: re-sign head when < 14d validity left → PR
  daily-monitor.yml                              ← poll each issuer's key-doc (Phase B5)
scripts/
  republish.mjs                                  ← invoked by monthly-republish.yml
  monitor.mjs                                    ← invoked by daily-monitor.yml
  lib/canonical.mjs                              ← RFC 8785-lite JCS — byte-equal mirror of @dekimuhq/anchors-envelope
  test-canonical.mjs                             ← hand-rolled JCS round-trip sanity check
  test-republish.mjs                             ← planner/signer checks + committed-chain verification
SECURITY.md
LICENSE                                          ← Apache-2.0
README.md
```

`chain/` is empty until Phase B6 commits the genesis list signed by the real
bootstrap key. Verifiers MUST fail-closed when the head is absent or stale
(per master plan §2.4 + Q1) — they SHOULD NOT silently fall back to "open
trust" on empty input.

---

## Governance

| Action | Approver(s) | Mechanism |
|---|---|---|
| Add a new trusted issuer | Founder + 1 maintainer | PR on this repo signed by both; merged manually after `daily-monitor` confirms the issuer's `/.well-known/dekimu-keys.json` resolves. |
| Revoke an issuer | Founder (sole, fast-path) | PR sets `revoked_at` on the issuer record; merged on same day. Bypass approval gate is intentional — revocation is always safe and time-critical. |
| Rotate the publisher key | Founder ceremony | New publisher key signs `v<N+1>` with the old `publisher_key` carried in `previous_publisher_key` (additive field, future-tracked). 90-day overlap window. MAJOR version bump on `@dekimuhq/anchors-trusted-issuers`. Cadence: 1 year. |
| Federation council vote | (Future) | v1 ships single-org allowlist. Federation handshake is Phase C of the cross-issuer interop master plan — not in scope here. |

The bootstrap publisher key fingerprint is published in
`@dekimuhq/anchors-trusted-issuers/src/bootstrap.ts` as the
`BOOTSTRAP_PUBLISHER_KEY` constant. Library consumers SHOULD pin this constant
as their first-load `bootstrap` value when constructing a
`makeDefaultTrustedIssuersSource`.

---

## Chain shape

Each list document is JSON conforming to `ar.trusted_issuers.v1`:

```jsonc
{
  "kind": "ar.trusted_issuers.v1",
  "version": 1,                              // monotonic, starts at 1
  "issued_at": "2026-05-19T00:00:00Z",       // RFC 3339, UTC
  "valid_until": "2026-06-19T00:00:00Z",     // typically issued_at + 30d
  "publisher": "did:web:dekimu.com",
  "publisher_key": "ed25519:<base64url(pubkey32)>",
  "previous_sha256": null,                   // null on genesis; "sha256:<hex>" otherwise
  "issuers": [
    {
      "iss": "did:web:<domain>",
      "added_at": "2026-05-01T00:00:00Z",
      "revoked_at": null,                    // ISO string when revoked
      "families": ["apr", "acr", "alr", "..."],
      "profiles_pinned": null,               // optional per-claim_type pin
      "notes": null
    }
  ],
  "sig": "<base64url(ed25519-sig-over-JCS-canonical-with-sig-null)>"
}
```

`previous_sha256` is `"sha256:" + sha256_hex(canonical(prev))` where
`canonical(prev)` is the JCS canonicalisation of the **signed** previous
document (i.e. `sig` field populated). Genesis has `previous_sha256: null`.

The signature is computed over the JCS canonicalisation of the document with
`sig` set to JSON `null` — the same convention as every other Anchored
Receipts standalone-attestation (`ar.continuity.v1`).

---

## How to propose adding an issuer

Until Phase C of the cross-issuer interop master plan ships the formal
federation handshake, additions are PR-driven on this repo. Steps:

1. Stand up a `did:web` identifier on your domain. Serve a valid
   `/.well-known/dekimu-keys.json` per the
   [`@dekimuhq/did-web-resolver`](https://github.com/dekimuhq) shape.
2. Open a PR adding your domain to the head list's `issuers` array, with:
   - `iss: "did:web:<your-domain>"`
   - `added_at` set to PR open date
   - `families: [...]` — only the family members you intend to issue for
   - `profiles_pinned: null` unless you want per-`claim_type` pinning
   - `notes`: 1–2 sentences explaining what your org does and how to reach you
3. The maintainer team will run the daily monitor against your domain. After
   3 consecutive clean polls, the PR is merged manually.
4. The next monthly republish (or a manual `workflow_dispatch` run) will
   produce `v<N+1>` with your record included, signed by the bootstrap key.

This is intentionally low-throughput — the v1 allowlist is targeted at <100
issuers. Higher scale requires the federation council (Phase C).

---

## Auto-republish cron

`monthly-republish.yml` (name kept for history) runs **weekly**, Mondays
03:17 UTC, plus `workflow_dispatch`. `scripts/republish.mjs`:

- Finds the head (highest `vNN`) and the newest doc whose `sig` verifies.
- Head unsigned or edited without re-signing (a merged monitor revocation or
  issuer-addition PR) → signs it as `v<last signed + 1>`, chained to the last
  signed doc, and removes the proposal file.
- Head signed with **≥ 14 days** of validity left → exits 0.
- Otherwise builds `v<N+1>`: same issuers, `issued_at` = now,
  `valid_until` = now + 30 days, `previous_sha256` linking back.
- Refuses a `SIGNING_KEY_BASE64` whose public key is not the doc's
  `publisher_key` (rotation is a founder ceremony, never a cron).
- Writes the new file **and `chain/head.json`** (byte copy of the newest
  signed doc), self-verifies, and the workflow opens a `republish/vNN` PR.
  Merging it is the publish gate.
- Renewal due but no signing key, or the `REPUBLISH_DISABLED=1` repo-variable
  kill switch → exits 2 (red), never a silent dry-run.

`verify.dekimu.com/.well-known/dekimu-trusted-issuers.json` serves
`chain/head.json` from `main` (1 h cache), so a merged republish is live within
the hour without a verify redeploy.

History: until 2026-10-19 the job ran on the 1st of the month, skipped heads
younger than 30 days (with a 30-day validity — so a mid-month doc always sat
expired for weeks) and stayed dry-run because `REPUBLISH_ENABLED` was never
provisioned. v01 expired 2026-08-16 behind four green runs.

---

## Daily monitor cron

`daily-monitor.yml` runs every day at 06:00 UTC. For each issuer in the head
list:

1. Fetch `https://<domain>/.well-known/dekimu-keys.json`.
2. (Optional) fetch `https://<domain>/.well-known/dekimu-issuer.json` manifest
   if present.
3. Both checks succeed → record success in `.github/state/monitor.json`.
4. Either check fails → increment per-issuer failure counter.
5. Counter ≥ 3 (three consecutive days) → open a draft PR setting
   `revoked_at: <now>` on that issuer with reason `"domain_unreachable"`.
   Founder approves the revocation manually.

The monitor cannot revoke unilaterally — it can only nominate.

---

## Single-org allowlist for v1

v1 of this allowlist is single-org-curated by Dekimu Labs SL. There is no
multi-party council, no on-chain voting, no automated admission. The
governance table above is the entire policy surface. This is intentional:

- Bootstrap simplicity. A single-key signature is the only thing every
  verifier needs to trust transitively.
- Easy revocation. One key, one signer, no quorum.
- Forward-compatible with Phase C federation, which will introduce a
  council-curated list as a SEPARATE `ar.trusted_issuers_council.v1` doc,
  leaving the v1 doc as the conservative single-org fallback.

Defer questions about multi-party governance to the [cross-issuer interop
master plan](https://github.com/dekimuhq/dekimu).

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
