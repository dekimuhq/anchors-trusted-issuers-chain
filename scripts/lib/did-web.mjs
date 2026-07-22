/**
 * `did:web:` → URL derivation for the daily monitor.
 *
 * MUST stay byte-compatible with `didWebToUrl()` in
 * `@dekimuhq/did-web-resolver` (anchors/did-web-resolver/src/did-web-url.ts).
 * That function is what production verifiers use to find an issuer's key doc;
 * if the monitor disagrees, it probes a URL nobody publishes and drives a
 * healthy issuer to automatic revocation on day 3.
 *
 * Guarded by `scripts/test-did-web.mjs`, which pins the same example vectors
 * the resolver's own docblock carries.
 */

const PREFIX = "did:web:";

/**
 * Base URL for a `did:web:` identifier, per W3C did:web v1.0. Path segments
 * are colon-separated in the DID and slash-separated in the URL, each
 * percent-decoded.
 *
 *   did:web:example.com            → https://example.com
 *   did:web:example.com:autonomy   → https://example.com/autonomy
 *   did:web:example.com:org%3A42   → https://example.com/org:42
 */
export function baseUrlOf(iss) {
  if (typeof iss !== "string" || !iss.startsWith(PREFIX)) {
    throw new Error(`unsupported iss scheme: ${iss} (only did:web supported)`);
  }
  const rest = iss.slice(PREFIX.length);
  if (rest.length === 0) throw new Error(`did:web: missing domain (${iss})`);
  const [domain, ...pathParts] = rest.split(":").map(decodeURIComponent);
  if (!domain) throw new Error(`did:web: missing domain (${iss})`);
  const suffix = pathParts.length > 0 ? `/${pathParts.join("/")}` : "";
  return `https://${domain}${suffix}`;
}

/**
 * Branch-name slug for a revocation proposal.
 *
 * Derived from the FULL DID, not just the domain: two issuers on one domain
 * (`did:web:dekimu.com` and `did:web:dekimu.com:autonomy`) previously
 * collapsed onto the same branch name and would have clobbered each other's
 * proposals.
 */
export function issuerSlug(iss) {
  if (typeof iss !== "string" || !iss.startsWith(PREFIX)) {
    throw new Error(`unsupported iss scheme: ${iss} (only did:web supported)`);
  }
  return iss.slice(PREFIX.length).replace(/[^a-z0-9.-]/gi, "_");
}
