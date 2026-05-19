/**
 * RFC 8785-lite canonical JSON.
 *
 * Standalone copy for the anchors-trusted-issuers-chain repo. Mirrors
 * `@dekimuhq/anchors-envelope/src/canonicalize.ts` byte-for-byte. This repo
 * must not depend on the monorepo at runtime (per Phase B4 plan, master plan
 * §2.5 — the chain repo is a passive mirror, fully self-contained).
 *
 * If you change this file, update `anchors/envelope/src/canonicalize.ts` in
 * the dekimuhq/dekimu monorepo first and prove byte-equality with a round-trip
 * fixture before mirroring the change here.
 *
 * Rules:
 *  - object keys sorted by UTF-16 code unit
 *  - no whitespace
 *  - numbers via Number.toString
 *  - strings UTF-8, NFC-normalised
 *  - rejects NaN, Infinity, undefined, functions, symbols, bigint
 *  - rejects circular references
 */

function sortValue(value, seen) {
  if (value === null) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: non-finite number");
    }
    return value;
  }
  if (typeof value === "bigint") {
    throw new Error("canonicalize: bigint not supported");
  }
  if (typeof value === "undefined") {
    throw new Error("canonicalize: undefined not supported");
  }
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Error(`canonicalize: ${typeof value} not supported`);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("canonicalize: circular reference");
    seen.add(value);
    const result = value.map((v) => sortValue(v, seen));
    seen.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (seen.has(value)) throw new Error("canonicalize: circular reference");
    seen.add(value);
    const keys = Object.keys(value).sort();
    const out = {};
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) {
        throw new Error(`canonicalize: undefined value at key "${k}"`);
      }
      out[k.normalize("NFC")] = sortValue(v, seen);
    }
    seen.delete(value);
    return out;
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

export function canonicalize(value) {
  const sorted = sortValue(value, new WeakSet());
  return JSON.stringify(sorted);
}
