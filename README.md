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
[`ar.trusted_issuers.v1`](https://github.com/dekimuhq/anchors-spec/blob/main/family-consistency.md)
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
| Add a new trusted issuer | Founder + 1 maintainer | PR on this repo adds the record to an **unsigned** next-version file, merged after `daily-monitor` confirms the issuer's `/.well-known/dekimu-keys.json` resolves. **The merge changes nothing that verifiers trust.** The trust change happens only when the founder dispatches `monthly-republish.yml` with `proposal_sha256` = the committed file's sha256 (see below). |
| Revoke an issuer | Founder (sole, fast-path) | PR (or the monitor's draft PR) sets `revoked_at` in an unsigned next-version file, merged the same day. The revocation becomes effective at the founder's `proposal_sha256` dispatch, which can follow the merge immediately. |
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
4. The founder's `workflow_dispatch` run with `proposal_sha256` (never the cron) will
   produce `v<N+1>` with your record included, signed by the bootstrap key.

This is intentionally low-throughput — the v1 allowlist is targeted at <100
issuers. Higher scale requires the federation council (Phase C).

---

## Auto-republish cron

`monthly-republish.yml` (name kept for history) runs **weekly**, Mondays
03:17 UTC, plus `workflow_dispatch`. **Merging a PR is never the approval for
changing who is trusted.** The two actions have different triggers:

| Action | What it signs | Cron | `workflow_dispatch` |
|---|---|---|---|
| `renew` | the validly-signed head **as is** (same issuer set), next `version`, fresh `issued_at` / `valid_until`, `previous_sha256` → head | yes, when < 14 d of the 30 d validity remain | yes (leave `proposal_sha256` empty) |
| `sign-proposal` | an unsigned or edited head (any issuer-set change: monitor revocation, issuer addition) — exactly the issuer set parsed from the committed bytes, chained to the last signed doc | **no** — red, "content change awaits founder dispatch", signs nothing | only with `proposal_sha256` = sha256 (hex) of that file as committed; a mismatch is red and signs nothing |

The dispatch naming the hash **is** the approval:

```sh
sha256sum chain/dekimu-trusted-issuers.vNN.<issued_at>.json   # on an up-to-date main
gh workflow run monthly-republish.yml -R dekimuhq/anchors-trusted-issuers-chain -f proposal_sha256=<hex>
```

(UNVERIFIED end to end: only this repo's Actions can read the real seed. The
script path is covered by `scripts/test-republish.mjs` with a throwaway key.)

Further guarantees:
- The script refuses a `SIGNING_KEY_BASE64` whose public key is not the doc's
  `publisher_key` (rotation is a founder ceremony, never a cron), and refuses
  if the issuer set of the signed output differs from its approved source.
- It writes the new file **and `chain/head.json`** (byte copy of the newest
  signed doc). The workflow stages only those paths (plus the deleted proposal
  file) and fails if anything else changed, so the commit/PR path cannot alter
  the issuer set. It then opens one `republish/vNN` PR; merging publishes it.
  If this repo's Actions may not open PRs (an org/repo setting), the run pushes the branch, notes it, and the PR is opened by Dekimu's `trusted-issuers-renew-pr` workflow or by hand: `gh pr create -R dekimuhq/anchors-trusted-issuers-chain --head republish/vNN --base main`.
  Editing that PR's branch before merge just turns the head into an unsigned
  proposal again — it never yields a trusted list.
- An action that is due but cannot be produced exits 2 (red): no signing key,
  a proposal on cron, a wrong or missing `proposal_sha256`, or the
  `REPUBLISH_DISABLED=1` repo-variable kill switch. It is never a silent
  dry-run.
- While an unsigned proposal sits on `main`, renewals stop too (the cron stays
  red), so a pending proposal must be dispatched or reverted before the signed
  head runs out.

`verify.dekimu.com/.well-known/dekimu-trusted-issuers.json` serves
`chain/head.json` from `main` (1 h cache), but only if it verifies under the
pinned publisher key; otherwise it serves its vendored floor copy.

History: until 2026-10-19 the job ran on the 1st of the month and skipped heads
younger than 30 days, even though each doc is valid for exactly 30 days, so a
mid-month doc always sat expired for weeks. It also stayed dry-run, because
`REPUBLISH_ENABLED` was never provisioned. v01 expired on 2026-08-16 while the
monthly runs kept passing green.

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
   Founder merges, then dispatches the republish with the file's
   `proposal_sha256`. The merge alone revokes nothing.

The monitor cannot revoke unilaterally — it can only nominate.

---

## Single-org allowlist for v1

v1 of this allowlist is single-org-curated by Dekimu. There is no
multi-party council, no on-chain voting, no automated admission. The
governance table above is the entire policy surface. This is intentional:

- Bootstrap simplicity. A single-key signature is the only thing every
  verifier needs to trust transitively.
- Easy revocation. One key, one signer, no quorum.
- Forward-compatible with Phase C federation, which will introduce a
  council-curated list as a SEPARATE `ar.trusted_issuers_council.v1` doc,
  leaving the v1 doc as the conservative single-org fallback.

Multi-party governance is deferred to the cross-issuer interop
master plan (Phase C); it is not yet published.

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

## Part of the Dekimu ecosystem

Built and maintained by [Dekimu](https://dekimu.com). The Dekimu ecosystem — [Dekimu Hub](https://app.dekimu.com) and the public verifier at [verify.dekimu.com](https://verify.dekimu.com) — is the reference implementation for this project. Sibling projects: [anchors-spec](https://github.com/dekimuhq/anchors-spec) · [dekimu-mcp](https://github.com/dekimuhq/dekimu-mcp) · [agents.txt](https://github.com/dekimuhq/agents-txt) · [regulation-as-code](https://github.com/dekimuhq/regulation-as-code) · [claude-memory](https://github.com/dekimuhq/claude-memory). All of them: https://dekimu.com/open-source.
