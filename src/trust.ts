import type { JWK } from "jose";
import { InvalidPayloadError, InvalidSignatureError } from "./errors.js";
import type { SigilTrustManifestV1 } from "./types.js";

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const HEX_64 = /^[a-f0-9]{64}$/;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const bytesFromBase64url = (value: string, label: string): Uint8Array => {
  if (!BASE64URL.test(value)) throw new InvalidPayloadError(`${label} must be base64url encoded`);
  try {
    const padding = "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + padding);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new InvalidPayloadError(`${label} must be base64url encoded`);
  }
};

const base64urlFromBytes = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");

const hexFromBytes = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const sha256 = async (bytes: Uint8Array): Promise<Uint8Array> => {
  if (!globalThis.crypto?.subtle) throw new InvalidPayloadError("Web Crypto SHA-256 is unavailable");
  const copy = new Uint8Array(bytes);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", copy.buffer));
};

const requireString = (value: unknown, field: string): string => {
  if (typeof value !== "string" || value.length === 0) {
    throw new InvalidPayloadError(`Trust manifest ${field} must be a non-empty string`);
  }
  return value;
};

const requireDate = (value: unknown, field: string): string => {
  const text = requireString(value, field);
  if (!Number.isFinite(Date.parse(text))) {
    throw new InvalidPayloadError(`Trust manifest ${field} must be an ISO timestamp`);
  }
  return text;
};

/** RFC 7638 SHA-256 thumbprint for an Ed25519 OKP public JWK. */
export const fingerprintJwk = async (jwk: unknown): Promise<string> => {
  if (!isRecord(jwk)) throw new InvalidPayloadError("JWK must be an object");
  const kty = requireString(jwk.kty, "jwk.kty");
  const crv = requireString(jwk.crv, "jwk.crv");
  const x = requireString(jwk.x, "jwk.x");
  if (kty !== "OKP" || crv !== "Ed25519" || !BASE64URL.test(x)) {
    throw new InvalidPayloadError("JWK must be an Ed25519 OKP public key");
  }
  const canonical = JSON.stringify({ crv, kty, x });
  return base64urlFromBytes(await sha256(new TextEncoder().encode(canonical)));
};

export const fingerprintEd25519RawKey = async (encodedKey: string): Promise<string> => {
  const raw = bytesFromBase64url(encodedKey, "Ed25519 public key");
  if (raw.length !== 32) throw new InvalidPayloadError("Ed25519 public key must be 32 bytes");
  return hexFromBytes(await sha256(raw));
};

export const fingerprintPqcRawKey = async (encodedKey: string): Promise<string> => {
  const raw = bytesFromBase64url(encodedKey, "PQC public key");
  if (raw.length === 0) throw new InvalidPayloadError("PQC public key must not be empty");
  return hexFromBytes(await sha256(raw));
};

export const validateTrustManifest = (value: unknown, now = new Date()): SigilTrustManifestV1 => {
  if (!isRecord(value)) throw new InvalidPayloadError("Trust manifest must be an object");
  if (value.schema !== "sigil-trust/v1") throw new InvalidPayloadError("Unsupported trust manifest schema");
  const issuer = requireString(value.issuer, "issuer");
  if (value.audience !== "sigil-sign") throw new InvalidPayloadError("Trust manifest audience must be sigil-sign");
  if (!Array.isArray(value.verifiedAlgorithms) || !value.verifiedAlgorithms.includes("EdDSA")) {
    throw new InvalidPayloadError("Trust manifest must verify EdDSA");
  }
  if (!Array.isArray(value.informationalAlgorithms) || value.informationalAlgorithms.some((item) => typeof item !== "string")) {
    throw new InvalidPayloadError("Trust manifest informationalAlgorithms is invalid");
  }
  const notBefore = requireDate(value.notBefore, "notBefore");
  const notAfter = requireDate(value.notAfter, "notAfter");
  const reviewAfter = requireDate(value.reviewAfter, "reviewAfter");
  if (Date.parse(notBefore) > now.getTime() || Date.parse(notAfter) <= now.getTime()) {
    throw new InvalidPayloadError("Trust manifest is outside its validity window");
  }
  if (value.revokedAt !== null) {
    requireDate(value.revokedAt, "revokedAt");
    throw new InvalidSignatureError("Trust manifest has been revoked");
  }
  if (!Array.isArray(value.attestationKeys) || value.attestationKeys.length === 0) {
    throw new InvalidPayloadError("Trust manifest requires attestationKeys");
  }
  const attestationKeys = value.attestationKeys.map((entry) => {
    if (!isRecord(entry)) throw new InvalidPayloadError("Trust attestation key is invalid");
    const kid = requireString(entry.kid, "attestationKeys.kid");
    const jwkThumbprint = requireString(entry.jwkThumbprint, "attestationKeys.jwkThumbprint");
    if (!BASE64URL.test(jwkThumbprint)) throw new InvalidPayloadError("Trust JWK thumbprint is invalid");
    return { kid, jwkThumbprint };
  });
  if (!isRecord(value.operatorKey)) throw new InvalidPayloadError("Trust manifest operatorKey is required");
  const fingerprint = requireString(value.operatorKey.fingerprint, "operatorKey.fingerprint");
  if (!HEX_64.test(fingerprint)) throw new InvalidPayloadError("Trust operator fingerprint is invalid");
  if (!isRecord(value.pqcKey)) throw new InvalidPayloadError("Trust manifest pqcKey is required");
  const pqcKid = requireString(value.pqcKey.kid, "pqcKey.kid");
  const pqcFingerprint = requireString(value.pqcKey.fingerprint, "pqcKey.fingerprint");
  if (!HEX_64.test(pqcFingerprint)) throw new InvalidPayloadError("Trust PQC fingerprint is invalid");
  return {
    schema: "sigil-trust/v1", issuer, audience: "sigil-sign",
    verifiedAlgorithms: value.verifiedAlgorithms as ["EdDSA", ...string[]],
    informationalAlgorithms: value.informationalAlgorithms as string[],
    notBefore, notAfter, reviewAfter, revokedAt: null, attestationKeys,
    operatorKey: { fingerprint }, pqcKey: { kid: pqcKid, fingerprint: pqcFingerprint },
  };
};

export const assertTrustedBundleKeys = async (
  trust: SigilTrustManifestV1,
  jwks: unknown,
  operatorPublicKey: unknown | undefined,
  expectedKid: string
): Promise<void> => {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) throw new InvalidPayloadError("Bundle jwks.json must contain keys");
  const seenKids = new Set<string>();
  for (const candidate of jwks.keys) {
    if (!isRecord(candidate) || typeof candidate.kid !== "string") {
      throw new InvalidPayloadError("Every bundle JWKS entry must have a kid");
    }
    if (seenKids.has(candidate.kid)) throw new InvalidSignatureError("Bundle JWKS contains a duplicate kid");
    seenKids.add(candidate.kid);
    const trustedKey = trust.attestationKeys.find((key) => key.kid === candidate.kid);
    if (!trustedKey || await fingerprintJwk(candidate as unknown as JWK) !== trustedKey.jwkThumbprint) {
      throw new InvalidSignatureError("Bundle JWKS contains a key that does not match the trust manifest");
    }
  }
  const expected = trust.attestationKeys.find((key) => key.kid === expectedKid);
  if (!expected) throw new InvalidSignatureError("Attestation kid is not trusted");
  const key = jwks.keys.find((candidate) => isRecord(candidate) && candidate.kid === expectedKid);
  if (!key) throw new InvalidSignatureError("Bundle JWKS does not contain the attestation kid");
  if (await fingerprintJwk(key as JWK) !== expected.jwkThumbprint) {
    throw new InvalidSignatureError("Bundle JWKS key does not match the trust manifest");
  }
  if (operatorPublicKey !== undefined) {
    if (!isRecord(operatorPublicKey)) throw new InvalidPayloadError("operator-public-key.json must be an object");
    const x = requireString(operatorPublicKey.x, "operator-public-key.x");
    if (await fingerprintEd25519RawKey(x) !== trust.operatorKey.fingerprint) {
      throw new InvalidSignatureError("Bundle operator key does not match the trust manifest");
    }
  }
};

export const assertTrustedInformationalPqcKey = async (
  trust: SigilTrustManifestV1,
  pqcKeys: unknown
): Promise<void> => {
  if (!isRecord(pqcKeys) || !Array.isArray(pqcKeys.keys)) {
    throw new InvalidPayloadError("Bundle pqc-keys.json must contain keys");
  }
  const key = pqcKeys.keys.find((candidate) => isRecord(candidate) && candidate.kid === trust.pqcKey.kid);
  if (!isRecord(key) || key.kty !== "ML-DSA" || key.alg !== "ML-DSA-65" || typeof key.publicKey !== "string") {
    throw new InvalidSignatureError("Bundle PQC key does not match the trust manifest");
  }
  if (await fingerprintPqcRawKey(key.publicKey) !== trust.pqcKey.fingerprint) {
    throw new InvalidSignatureError("Bundle PQC key does not match the trust manifest");
  }
};
