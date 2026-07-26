import { compactVerify, createLocalJWKSet, decodeJwt, decodeProtectedHeader } from "jose";
import { hashPgCommitV1 } from "@sigilcore/warrant-core";
import { createWebCryptoAdapter } from "@sigilcore/warrant-core/crypto/browser";
import { ExpiredAttestationError, InvalidAlgorithmError, InvalidPayloadError, InvalidSignatureError } from "./errors.js";
import { assertTrustedBundleKeys, validateTrustManifest } from "./trust.js";
import type { ProvingGroundVerificationOptions, ProvingGroundVerificationResult, VerificationMode } from "./types.js";

const HEX_64 = /^[a-f0-9]{64}$/;
const requireString = (value: unknown, name: string): string => {
  if (typeof value !== "string" || value.length === 0) throw new InvalidPayloadError(`${name} must be a non-empty string`);
  return value;
};
const requireInteger = (value: unknown, name: string): number => {
  if (!Number.isSafeInteger(value)) throw new InvalidPayloadError(`${name} must be an integer`);
  return value as number;
};

const resolveVerificationMode = (value: unknown): VerificationMode => {
  if (value === undefined) return "execution";
  if (value === "execution" || value === "audit") return value;
  throw new InvalidPayloadError("mode must be execution or audit");
};

const resolveNow = (value: unknown): Date => {
  const now = value ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new InvalidPayloadError("now must be a valid Date");
  }
  return now;
};

const hexFromBytes = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const webCryptoAdapter = () => {
  if (!globalThis.crypto?.subtle) throw new InvalidPayloadError("Web Crypto is unavailable");
  return createWebCryptoAdapter(globalThis.crypto);
};

const isCanonicalBase64url = (segment: string): boolean => {
  try {
    const padding = "=".repeat((4 - (segment.length % 4)) % 4);
    const binary = atob(segment.replace(/-/g, "+").replace(/_/g, "/") + padding);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "") === segment;
  } catch {
    return false;
  }
};

const assertCanonicalCompactJwt = (jwt: string): void => {
  const segments = jwt.split(".");
  if (segments.length !== 3 || segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment))) {
    throw new InvalidPayloadError("JWT must use compact base64url serialization");
  }
  if (segments.some((segment) => !isCanonicalBase64url(segment))) {
    throw new InvalidSignatureError("JWT contains a non-canonical base64url segment");
  }
};

const verifyJwtSignature = async (jwt: string, jwks: unknown): Promise<void> => {
  try {
    await compactVerify(jwt, createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]), { algorithms: ["EdDSA"] });
  } catch (error) {
    throw new InvalidSignatureError(error instanceof Error ? error.message : "JWT signature verification failed");
  }
};

const validateIssuer = (payload: Record<string, unknown>, expectedIssuer: string): string => {
  const issuer = requireString(payload.iss, "iss");
  if (issuer !== expectedIssuer) throw new InvalidSignatureError("JWT issuer does not match the trust manifest");
  return issuer;
};

const validateAudience = (value: unknown, expectedAudience: string): void => {
  const includesAudience = value === expectedAudience || (Array.isArray(value) && value.includes(expectedAudience));
  if (!includesAudience) throw new InvalidPayloadError("JWT audience must include sigil-sign");
};

const validateMatchingKid = (payload: Record<string, unknown>, headerKid: string): string => {
  const payloadKid = requireString(payload.kid, "JWT payload kid");
  if (payloadKid !== headerKid) throw new InvalidSignatureError("JWT header and payload kid do not match");
  return payloadKid;
};

const readAttestationLifetime = (payload: Record<string, unknown>): { exp: number; iat: number } => {
  const exp = requireInteger(payload.exp, "exp");
  const iat = requireInteger(payload.iat, "iat");
  if (exp <= iat) throw new InvalidPayloadError("attestation lifetime must be between one and 60 seconds");
  if (exp - iat > 60) throw new InvalidPayloadError("attestation lifetime must be between one and 60 seconds");
  return { exp, iat };
};

const validateAttestationTime = (exp: number, iat: number, mode: VerificationMode, now: Date): boolean => {
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (iat > nowSeconds + 5) throw new InvalidPayloadError("iat claim is beyond the five-second clock tolerance");
  const authorizationExpired = exp <= nowSeconds;
  if (mode === "execution" && authorizationExpired) throw new ExpiredAttestationError();
  return authorizationExpired;
};

const requireSha256Hex = (value: unknown, name: string): string => {
  const hash = requireString(value, name);
  if (!HEX_64.test(hash)) throw new InvalidPayloadError(`${name} must be lowercase SHA-256 hex`);
  return hash;
};

const validateAttestationClaims = (
  payload: Record<string, unknown>,
  issuer: string,
  audience: string,
  headerKid: string,
  mode: VerificationMode,
  now: Date
) => {
  const verifiedIssuer = validateIssuer(payload, issuer);
  validateAudience(payload.aud, audience);
  const payloadKid = validateMatchingKid(payload, headerKid);
  const { exp, iat } = readAttestationLifetime(payload);
  const authorizationExpired = validateAttestationTime(exp, iat, mode, now);
  const policyHash = requireSha256Hex(payload.policyHash, "policyHash");
  const intentHash = requireSha256Hex(payload.intentHash, "intentHash");
  return { issuer: verifiedIssuer, payloadKid, exp, iat, authorizationExpired, policyHash, intentHash };
};

/** Verify the CC-1 profile without changing the legacy strict verifier. */
export const verifyProvingGroundAttestation = async (
  jwt: string,
  options: ProvingGroundVerificationOptions
): Promise<ProvingGroundVerificationResult> => {
  const mode = resolveVerificationMode(options.mode);
  const now = resolveNow(options.now);
  const trust = validateTrustManifest(options.trust, now);
  assertCanonicalCompactJwt(jwt);
  const header = decodeProtectedHeader(jwt);
  if (header.alg !== "EdDSA") throw new InvalidAlgorithmError(`Expected alg=EdDSA, got alg=${header.alg}`);
  const headerKid = requireString(header.kid, "JWT header kid");
  await assertTrustedBundleKeys(trust, options.jwks, undefined, headerKid);
  await verifyJwtSignature(jwt, options.jwks);
  const payload = decodeJwt(jwt) as Record<string, unknown>;
  const claims = validateAttestationClaims(payload, trust.issuer, trust.audience, headerKid, mode, now);
  if (!HEX_64.test(options.request.txCommit)) throw new InvalidPayloadError("request txCommit must be lowercase SHA-256 hex");
  const adapter = webCryptoAdapter();
  const recomputedCommit = await hashPgCommitV1(adapter, options.request.intent as never);
  if (recomputedCommit !== options.request.txCommit) throw new InvalidPayloadError("request txCommit does not match pg-commit-v1 intent");
  const recomputedIntentHash = hexFromBytes(await adapter.sha256(new TextEncoder().encode(options.request.txCommit)));
  if (recomputedIntentHash !== claims.intentHash) throw new InvalidPayloadError("intentHash does not bind the request txCommit");
  return {
    mode, authorizationExpired: claims.authorizationExpired, protectedHeader: header as Record<string, unknown>,
    claims: { iss: claims.issuer, aud: trust.audience, exp: claims.exp, iat: claims.iat, kid: claims.payloadKid, intentHash: claims.intentHash, policyHash: claims.policyHash },
    commitment: { txCommit: recomputedCommit, intentHash: recomputedIntentHash },
  };
};
