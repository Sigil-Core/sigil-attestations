import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK, type JWK } from "jose";
import { frameWarrantMarkdownBytes, hashPgCommitV1, hashPolicy, parsePolicyMarkdown } from "@sigilcore/warrant-core";
import { createWebCryptoAdapter } from "@sigilcore/warrant-core/crypto/browser";
import { AuthorizeVerificationError, AuthorizeVerificationErrorCode } from "./errors.js";
import type {
  AuditAuthorizeProof,
  AuditAuthorizeProofOptions,
  AuthorizeReplayConsumeResult,
  AuthorizeProofCommon,
  AuthorizeReplayStore,
  AuthorizeTrustKey,
  ExecutionAuthorizeProof,
  JsonValue,
  SigilAuthorizeProofBundleV1,
  SigilAuthorizeTrustV1,
} from "./types.js";

const BUNDLE_LIMIT_BYTES = 1024 * 1024;
const WARRANTY_LIMIT_BYTES = 256 * 1024;
const TOKEN_LIFETIME_SECONDS = 60;
const FUTURE_IAT_TOLERANCE_SECONDS = 5;
const REPLAY_RETENTION_SECONDS = 300;
const STORE_CLOCK_FAIL_SECONDS = 30;
const MAX_JSON_NESTING = 64;
const HEX_64 = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

type RecordValue = Record<string, unknown>;

const fail = (code: AuthorizeVerificationErrorCode, message: string): never => {
  throw new AuthorizeVerificationError(code, message);
};

const isRecord = (value: unknown): value is RecordValue =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasOwn = (value: RecordValue, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

const requireString = (value: unknown, field: string, code = AuthorizeVerificationErrorCode.BUNDLE_SCHEMA): string => {
  if (typeof value !== "string" || value.length === 0) fail(code, `${field} must be a non-empty string`);
  return value as string;
};

const requireInteger = (value: unknown, field: string, code = AuthorizeVerificationErrorCode.BUNDLE_SCHEMA): number => {
  if (!Number.isSafeInteger(value)) fail(code, `${field} must be a safe integer`);
  return value as number;
};

const assertExactKeys = (value: RecordValue, allowed: readonly string[], field: string): void => {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, `${field} contains an unknown property`);
  }
};

// skipcq: JS-R1005 - Recursive JSON validation deliberately enumerates every accepted JSON type before proof parsing.
const assertJsonValue: (value: unknown, field: string) => asserts value is JsonValue = (value, field) => {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, `${field} contains a non-finite number`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertJsonValue(entry, `${field}[${index}]`));
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) assertJsonValue(entry, `${field}.${key}`);
    return;
  }
  fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, `${field} is not JSON`);
};

/**
 * JSON.parse loses duplicate-property evidence. This small lexical pass
 * validates JSON structure while retaining every decoded object key.
 */
const assertNoDuplicateJsonProperties = (input: string): void => {
  let index = 0;
  // skipcq: JS-R1005 - Whitespace is limited to the four JSON grammar code points before each parse step.
  const whitespace = (): void => {
    while (index < input.length && (input[index] === " " || input[index] === "\n" || input[index] === "\r" || input[index] === "\t")) index += 1;
  };
  const invalid = (): never => fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "proof bundle must contain valid JSON");
  // skipcq: JS-R1005 - This is an intentionally fail-closed JSON string scanner that retains exact object-key evidence.
  const string = (): string => {
    if (input[index] !== '"') invalid();
    const start = index;
    index += 1;
    while (index < input.length) {
      const character = input[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(input.slice(start, index)) as string;
        } catch {
          return invalid();
        }
      }
      if (character < " ") invalid();
      if (character === "\\") {
        index += 1;
        const escape = input[index];
        if (escape === undefined || !'"\\/bfnrtu'.includes(escape)) invalid();
        if (escape === "u") {
          const hex = input.slice(index + 1, index + 5);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) invalid();
          index += 4;
        }
      }
      index += 1;
    }
    return invalid();
  };
  // skipcq: JS-R1005 - The recursive lexical parser preserves duplicate-key detection that JSON.parse discards.
  const value = (depth = 0): void => {
    if (depth >= MAX_JSON_NESTING) {
      fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "proof bundle exceeds the maximum JSON nesting depth");
    }
    whitespace();
    const character = input[index];
    if (character === "{") {
      index += 1;
      whitespace();
      const seen = new Set<string>();
      if (input[index] === "}") {
        index += 1;
        return;
      }
      while (true) {
        whitespace();
        const key = string();
        if (seen.has(key)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "proof bundle contains a duplicate JSON property");
        seen.add(key);
        whitespace();
        if (input[index] !== ":") invalid();
        index += 1;
        value(depth + 1);
        whitespace();
        if (input[index] === "}") {
          index += 1;
          return;
        }
        if (input[index] !== ",") invalid();
        index += 1;
      }
    }
    if (character === "[") {
      index += 1;
      whitespace();
      if (input[index] === "]") {
        index += 1;
        return;
      }
      while (true) {
        value(depth + 1);
        whitespace();
        if (input[index] === "]") {
          index += 1;
          return;
        }
        if (input[index] !== ",") invalid();
        index += 1;
      }
    }
    if (character === '"') {
      string();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (input.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(input.slice(index));
    const matched = number?.[0] ?? invalid();
    index += matched.length;
  };
  value();
  whitespace();
  if (index !== input.length) invalid();
};

// skipcq: JS-R1005 - This raw-byte boundary checks every encoding ambiguity before JSON parsing or cryptographic work.
const decodeRawBundle = (rawBundle: Uint8Array): unknown => {
  if (rawBundle.byteLength > BUNDLE_LIMIT_BYTES) {
    return fail(AuthorizeVerificationErrorCode.BUNDLE_TOO_LARGE, "proof bundle exceeds 1 MiB");
  }
  let text = "";
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(rawBundle);
  } catch {
    return fail(AuthorizeVerificationErrorCode.BUNDLE_ENCODING, "proof bundle is not valid UTF-8");
  }
  if (text.charCodeAt(0) === 0xfeff || (rawBundle[0] === 0xef && rawBundle[1] === 0xbb && rawBundle[2] === 0xbf)) {
    return fail(AuthorizeVerificationErrorCode.BUNDLE_ENCODING, "proof bundle must not include a UTF-8 BOM");
  }
  assertNoDuplicateJsonProperties(text);
  try {
    return JSON.parse(text);
  } catch {
    return fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "proof bundle must contain valid JSON");
  }
};

// skipcq: JS-R1005 - This explicit schema boundary rejects ambiguous proof fields before signature verification.
const parseProofBundle = (value: unknown): SigilAuthorizeProofBundleV1 => {
  if (!isRecord(value)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "proof bundle must be an object");
  const bundle = value as RecordValue;
  assertExactKeys(bundle, ["bundle_version", "verification_profile", "token", "request", "policy", "trust_reference"], "proof bundle");
  if (bundle.bundle_version !== "sigil-authorize-proof/v1") {
    fail(AuthorizeVerificationErrorCode.PROFILE_UNKNOWN, "unsupported proof bundle version");
  }
  if (bundle.verification_profile !== "sigil-sign-authorize-v1") {
    fail(AuthorizeVerificationErrorCode.PROFILE_UNKNOWN, "unsupported verification profile");
  }
  const token = requireString(bundle.token, "token");
  if (!isRecord(bundle.request)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "request must be an object");
  const request = bundle.request as RecordValue;
  assertExactKeys(request, ["agentId", "framework", "chainId", "txCommit", "intent"], "request");
  const agentId = requireString(request.agentId, "request.agentId");
  const framework = requireString(request.framework, "request.framework");
  const txCommit = requireString(request.txCommit, "request.txCommit");
  if (!HEX_64.test(txCommit)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "request.txCommit must be lowercase SHA-256 hex");
  if (!hasOwn(request, "intent") || !isRecord(request.intent)) {
    fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "request.intent must be a JSON object");
  }
  assertJsonValue(request.intent, "request.intent");
  const chainId = hasOwn(request, "chainId")
    ? requireInteger(request.chainId, "request.chainId", AuthorizeVerificationErrorCode.CLAIM_MISMATCH)
    : undefined;
  if (chainId !== undefined && chainId <= 0) fail(AuthorizeVerificationErrorCode.CLAIM_MISMATCH, "request.chainId must be positive");
  if (!isRecord(bundle.policy)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "policy must be an object");
  const policy = bundle.policy as RecordValue;
  assertExactKeys(policy, ["warranty_md"], "policy");
  const warrantyMd = requireString(policy.warranty_md, "policy.warranty_md");
  if (!isRecord(bundle.trust_reference)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust_reference must be an object");
  const trustReference = bundle.trust_reference as RecordValue;
  assertExactKeys(trustReference, ["manifest_sha256", "issuer", "audience"], "trust_reference");
  const manifestSha256 = requireString(trustReference.manifest_sha256, "trust_reference.manifest_sha256");
  if (!HEX_64.test(manifestSha256)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust_reference.manifest_sha256 must be lowercase SHA-256 hex");
  return {
    bundle_version: "sigil-authorize-proof/v1",
    verification_profile: "sigil-sign-authorize-v1",
    token,
    request: {
      agentId,
      framework,
      ...(chainId === undefined ? {} : { chainId }),
      txCommit,
      intent: request.intent as JsonValue,
    },
    policy: { warranty_md: warrantyMd },
    trust_reference: {
      manifest_sha256: manifestSha256,
      issuer: requireString(trustReference.issuer, "trust_reference.issuer"),
      audience: requireString(trustReference.audience, "trust_reference.audience"),
    },
  };
};

// skipcq: JS-R1005 - Trust-key validation intentionally checks every authority-bearing member before importJWK.
const requireTrustKey = (value: unknown): AuthorizeTrustKey => {
  if (!isRecord(value)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust key must be an object");
  const key = value as RecordValue;
  assertExactKeys(key, ["kid", "jwk", "not_before", "not_after", "revoked_at"], "trust key");
  if (!isRecord(key.jwk)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust key JWK must be an object");
  const jwk = key.jwk as RecordValue;
  assertExactKeys(jwk, ["kty", "crv", "x", "alg"], "trust key JWK");
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || !BASE64URL.test(jwk.x)) {
    fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust key must be an Ed25519 public JWK");
  }
  if (jwk.alg !== undefined && jwk.alg !== "EdDSA") {
    fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust key JWK alg must be EdDSA when present");
  }
  const notBefore = requireInteger(key.not_before, "trust key not_before");
  const notAfter = requireInteger(key.not_after, "trust key not_after");
  const revokedAt = key.revoked_at === undefined ? undefined : requireInteger(key.revoked_at, "trust key revoked_at");
  if (notAfter <= notBefore || (revokedAt !== undefined && revokedAt <= notBefore)) {
    fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust key has an invalid validity window");
  }
  return {
    kid: requireString(key.kid, "trust key kid"),
    jwk: {
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x as string,
      ...(jwk.alg === undefined ? {} : { alg: "EdDSA" }),
    },
    not_before: notBefore,
    not_after: notAfter,
    ...(revokedAt === undefined ? {} : { revoked_at: revokedAt }),
  };
};

/** Validate an independently obtained v1 trust configuration before use. */
// skipcq: JS-R1005 - The trust-root schema must reject every malformed key list and duplicate kid before use.
export const validateAuthorizeTrust = (value: unknown): SigilAuthorizeTrustV1 => {
  if (!isRecord(value)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust configuration must be an object");
  const trust = value as RecordValue;
  assertExactKeys(trust, ["schema", "manifest_sha256", "issuer", "audience", "keys"], "trust configuration");
  if (trust.schema !== "sigil-authorize-trust/v1") fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "unsupported trust configuration schema");
  const manifestSha256 = requireString(trust.manifest_sha256, "trust manifest_sha256");
  if (!HEX_64.test(manifestSha256)) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust manifest_sha256 must be lowercase SHA-256 hex");
  if (!Array.isArray(trust.keys) || trust.keys.length === 0) fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust configuration must contain keys");
  const keys = (trust.keys as unknown[]).map(requireTrustKey);
  if (new Set(keys.map((key) => key.kid)).size !== keys.length) {
    fail(AuthorizeVerificationErrorCode.BUNDLE_SCHEMA, "trust configuration contains duplicate kids");
  }
  return {
    schema: "sigil-authorize-trust/v1",
    manifest_sha256: manifestSha256,
    issuer: requireString(trust.issuer, "trust issuer"),
    audience: requireString(trust.audience, "trust audience"),
    keys,
  };
};

const webCryptoAdapter = () => {
  if (!globalThis.crypto?.subtle) fail(AuthorizeVerificationErrorCode.BUNDLE_ENCODING, "Web Crypto is unavailable");
  return createWebCryptoAdapter(globalThis.crypto);
};

const hex = (bytes: Uint8Array): string => Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");

const sameText = (left: string, right: string): boolean => {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
  return difference === 0;
};

// skipcq: JS-R1005 - Compact JWS segments must reject padding and non-zero unused bits before replay-id derivation.
const isCanonicalBase64urlSegment = (segment: string): boolean => {
  if (!BASE64URL.test(segment)) return false;
  const remainder = segment.length % 4;
  if (remainder === 1) return false;
  if (remainder === 0) return true;
  const lastCharacter = BASE64URL_ALPHABET.indexOf(segment[segment.length - 1]);
  return remainder === 2 ? (lastCharacter & 0x0f) === 0 : (lastCharacter & 0x03) === 0;
};

const assertCanonicalCompactJws = (token: string): void => {
  const segments = token.split(".");
  if (segments.length !== 3 || !segments.every(isCanonicalBase64urlSegment)) {
    fail(AuthorizeVerificationErrorCode.SIGNATURE, "token must use canonical unpadded base64url compact serialization");
  }
};

// skipcq: JS-R1005 - This ordered JWT boundary verifies EdDSA before admitting claims to the authorization path.
const readPayload = async (bundle: SigilAuthorizeProofBundleV1, trust: SigilAuthorizeTrustV1): Promise<{ payload: RecordValue; key: AuthorizeTrustKey; headerKid: string }> => {
  assertCanonicalCompactJws(bundle.token);
  let header: RecordValue = {};
  try {
    header = decodeProtectedHeader(bundle.token) as RecordValue;
  } catch {
    fail(AuthorizeVerificationErrorCode.SIGNATURE, "token protected header is malformed");
  }
  if (header.alg !== "EdDSA") fail(AuthorizeVerificationErrorCode.ALG_UNSUPPORTED, "token algorithm must be EdDSA");
  const headerKid = requireString(header.kid, "token protected header kid", AuthorizeVerificationErrorCode.KID_UNKNOWN);
  const matchedKey = trust.keys.find((entry) => sameText(entry.kid, headerKid));
  if (!matchedKey) fail(AuthorizeVerificationErrorCode.KID_UNKNOWN, "token kid is not trusted");
  const key = matchedKey as AuthorizeTrustKey;
  let importedKey: CryptoKey | Uint8Array;
  try {
    importedKey = await importJWK(key.jwk as JWK, "EdDSA");
    await compactVerify(bundle.token, importedKey, { algorithms: ["EdDSA"] });
  } catch {
    fail(AuthorizeVerificationErrorCode.SIGNATURE, "token signature verification failed");
  }
  try {
    const payload = decodeJwt(bundle.token);
    if (!isRecord(payload)) fail(AuthorizeVerificationErrorCode.SIGNATURE, "token payload must be an object");
    return { payload, key, headerKid };
  } catch (error) {
    if (error instanceof AuthorizeVerificationError) throw error;
    return fail(AuthorizeVerificationErrorCode.SIGNATURE, "token payload is malformed");
  }
};

const requireClaimString = (payload: RecordValue, field: string): string =>
  requireString(payload[field], `token ${field}`, AuthorizeVerificationErrorCode.CLAIM_MISMATCH);

const claimHasAudience = (value: unknown, expected: string): boolean => {
  if (typeof value === "string") return sameText(value, expected);
  return Array.isArray(value) && value.length > 0 && value.every((entry) => typeof entry === "string") && value.some((entry) => sameText(entry, expected));
};

const requireHash = (value: unknown, field: string, code: AuthorizeVerificationErrorCode): string => {
  const result = requireString(value, field, code);
  if (!HEX_64.test(result)) fail(code, `${field} must be lowercase SHA-256 hex`);
  return result;
};

const readChainId = (value: RecordValue, field: string): number | undefined => {
  if (!hasOwn(value, "chainId")) return undefined;
  const chainId = requireInteger(value.chainId, field, AuthorizeVerificationErrorCode.CLAIM_MISMATCH);
  if (chainId <= 0) fail(AuthorizeVerificationErrorCode.CLAIM_MISMATCH, `${field} must be positive`);
  return chainId;
};

// skipcq: JS-R1005 - Each independent claim and trust-window condition is fail-closed and security relevant.
const validateClaims = (
  bundle: SigilAuthorizeProofBundleV1,
  trust: SigilAuthorizeTrustV1,
  payload: RecordValue,
  headerKid: string,
  key: AuthorizeTrustKey,
  verificationTime: number,
  mode: "execution" | "audit"
): Omit<AuthorizeProofCommon, "profile" | "txCommit" | "intentHash" | "policyHash"> & { intentHash: string; policyHash: string } => {
  const issuer = requireClaimString(payload, "iss");
  if (!sameText(issuer, trust.issuer)) fail(AuthorizeVerificationErrorCode.ISSUER, "token issuer does not match trusted issuer");
  if (!claimHasAudience(payload.aud, trust.audience)) {
    fail(AuthorizeVerificationErrorCode.AUDIENCE, "token audience does not contain the trusted audience");
  }
  const payloadKid = requireClaimString(payload, "kid");
  if (!sameText(payloadKid, headerKid)) fail(AuthorizeVerificationErrorCode.KID_MISMATCH, "token header and payload kid differ");
  if (!sameText(requireClaimString(payload, "agentId"), bundle.request.agentId) || !sameText(requireClaimString(payload, "framework"), bundle.request.framework)) {
    fail(AuthorizeVerificationErrorCode.CLAIM_MISMATCH, "token identity claims do not match request");
  }
  const signedChainId = readChainId(payload, "token chainId");
  const requestChainId = bundle.request.chainId;
  if (signedChainId !== requestChainId) {
    fail(AuthorizeVerificationErrorCode.CLAIM_MISMATCH, "token chainId must exactly match the request");
  }
  const iat = requireInteger(payload.iat, "token iat", AuthorizeVerificationErrorCode.LIFETIME);
  const exp = requireInteger(payload.exp, "token exp", AuthorizeVerificationErrorCode.LIFETIME);
  if (exp <= iat || exp - iat > TOKEN_LIFETIME_SECONDS) fail(AuthorizeVerificationErrorCode.LIFETIME, "token lifetime must be between one and 60 seconds");
  if (iat > verificationTime + FUTURE_IAT_TOLERANCE_SECONDS) fail(AuthorizeVerificationErrorCode.IAT_FUTURE, "token iat is too far in the future");
  if (mode === "execution" && verificationTime >= exp) fail(AuthorizeVerificationErrorCode.EXPIRED, "token has expired");
  if (iat < key.not_before || iat >= key.not_after) {
    fail(AuthorizeVerificationErrorCode.TRUST_WINDOW, "trusted key is outside its validity window");
  }
  if (mode === "execution" && (verificationTime < key.not_before || verificationTime >= key.not_after)) {
    fail(AuthorizeVerificationErrorCode.TRUST_WINDOW, "trusted key is outside its validity window");
  }
  if (key.revoked_at !== undefined && (iat >= key.revoked_at || verificationTime >= key.revoked_at)) {
    fail(AuthorizeVerificationErrorCode.TRUST_REVOKED, "trusted key is revoked at verification time");
  }
  return {
    issuer,
    kid: payloadKid,
    issuedAt: iat,
    expiresAt: exp,
    intentHash: requireHash(payload.intentHash, "token intentHash", AuthorizeVerificationErrorCode.INTENT_HASH_MISMATCH),
    policyHash: requireHash(payload.policyHash, "token policyHash", AuthorizeVerificationErrorCode.POLICY_HASH_MISMATCH),
  };
};

// skipcq: JS-R1005 - Commitment and strict-Warrant checks remain sequenced to preserve distinct stable failure codes.
const verifyCommitmentAndPolicy = async (
  bundle: SigilAuthorizeProofBundleV1,
  signedIntentHash: string,
  signedPolicyHash: string
): Promise<{ txCommit: string; intentHash: string; policyHash: string }> => {
  const adapter = webCryptoAdapter();
  let txCommit = "";
  try {
    txCommit = await hashPgCommitV1(adapter, bundle.request.intent as Parameters<typeof hashPgCommitV1>[1]);
  } catch {
    fail(AuthorizeVerificationErrorCode.COMMIT_MISMATCH, "request intent is not a valid pg-commit-v1 value");
  }
  if (!HEX_64.test(txCommit) || !sameText(txCommit, bundle.request.txCommit)) {
    fail(AuthorizeVerificationErrorCode.COMMIT_MISMATCH, "request txCommit does not match pg-commit-v1 intent");
  }
  const intentHash = hex(await adapter.sha256(new TextEncoder().encode(txCommit)));
  if (!sameText(intentHash, signedIntentHash)) {
    fail(AuthorizeVerificationErrorCode.INTENT_HASH_MISMATCH, "token intentHash does not bind request txCommit");
  }
  const warrantyBytes = new TextEncoder().encode(bundle.policy.warranty_md);
  if (warrantyBytes.byteLength > WARRANTY_LIMIT_BYTES) fail(AuthorizeVerificationErrorCode.POLICY_TOO_LARGE, "warranty_md exceeds 256 KiB");
  let policyHash = "";
  try {
    const framed = frameWarrantMarkdownBytes(warrantyBytes, { maxBytes: WARRANTY_LIMIT_BYTES });
    const unsigned = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(framed.unsigned);
    policyHash = await hashPolicy(adapter, parsePolicyMarkdown(unsigned));
  } catch {
    fail(AuthorizeVerificationErrorCode.POLICY_PARSE, "warranty_md must be a strictly framed signed Warrant");
  }
  if (!HEX_64.test(policyHash) || !sameText(policyHash, signedPolicyHash)) {
    fail(AuthorizeVerificationErrorCode.POLICY_HASH_MISMATCH, "token policyHash does not match warranty_md");
  }
  return { txCommit, intentHash, policyHash };
};

const verifyBase = async (
  rawBundle: Uint8Array,
  trustValue: SigilAuthorizeTrustV1,
  verificationTime: number,
  mode: "execution" | "audit"
): Promise<{ bundle: SigilAuthorizeProofBundleV1; common: AuthorizeProofCommon }> => {
  const bundle = parseProofBundle(decodeRawBundle(rawBundle));
  const trust = validateAuthorizeTrust(trustValue);
  if (
    !sameText(bundle.trust_reference.manifest_sha256, trust.manifest_sha256) ||
    !sameText(bundle.trust_reference.issuer, trust.issuer) ||
    !sameText(bundle.trust_reference.audience, trust.audience)
  ) {
    fail(AuthorizeVerificationErrorCode.TRUST_REFERENCE_MISMATCH, "bundle trust reference does not match configured trust");
  }
  const { payload, key, headerKid } = await readPayload(bundle, trust);
  const claims = validateClaims(bundle, trust, payload, headerKid, key, verificationTime, mode);
  const hashes = await verifyCommitmentAndPolicy(bundle, claims.intentHash, claims.policyHash);
  return {
    bundle,
    common: {
      profile: "sigil-sign-authorize-v1",
      issuer: claims.issuer,
      kid: claims.kid,
      txCommit: hashes.txCommit,
      intentHash: hashes.intentHash,
      policyHash: hashes.policyHash,
      issuedAt: claims.issuedAt,
      expiresAt: claims.expiresAt,
    },
  };
};

/**
 * Verify an authority-bearing authorization. The caller supplies a durable
 * atomic replay adapter. No caller-controlled execution time is accepted.
 */
// skipcq: JS-R1005 - The authorization path keeps replay and clock-fence outcomes explicit and fail-closed.
export const verifyAuthorizeProofBundleForExecution = async (
  rawBundle: Uint8Array,
  trust: SigilAuthorizeTrustV1,
  replayStore: AuthorizeReplayStore
): Promise<ExecutionAuthorizeProof> => {
  const now = Math.floor(Date.now() / 1000);
  const { bundle, common } = await verifyBase(rawBundle, trust, now, "execution");
  const adapter = webCryptoAdapter();
  const replayId = hex(await adapter.sha256(new TextEncoder().encode([
    bundle.verification_profile,
    common.issuer,
    trust.audience,
    bundle.token,
  ].join("\u0000"))));
  let consumeResult: AuthorizeReplayConsumeResult | undefined;
  try {
    consumeResult = await replayStore.consumeIfUnused(
      replayId,
      common.expiresAt,
      common.expiresAt + REPLAY_RETENTION_SECONDS,
      now,
      STORE_CLOCK_FAIL_SECONDS
    );
  } catch {
    fail(AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE, "replay store is unavailable");
  }
  const consumeStatus = isRecord(consumeResult) ? consumeResult.status : undefined;
  if (typeof consumeStatus !== "string") {
    fail(AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE, "replay store returned an invalid result");
  }
  if (consumeStatus === "clock_drift") {
    fail(AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE, "replay store clock drift exceeds 30 seconds before consume");
  }
  if (consumeStatus === "replayed") {
    fail(AuthorizeVerificationErrorCode.REPLAY_DENIED, "authorization token has already been consumed");
  }
  if (consumeStatus === "expired") {
    fail(AuthorizeVerificationErrorCode.EXPIRED, "authorization token expired before replay consumption");
  }
  if (consumeStatus !== "consumed") {
    fail(AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE, "replay store returned an invalid status");
  }
  if (Math.floor(Date.now() / 1000) >= common.expiresAt) {
    fail(AuthorizeVerificationErrorCode.EXPIRED, "authorization token expired during replay consumption");
  }
  return { ...common, mode: "execution" } as ExecutionAuthorizeProof;
};

/** Verify historical evidence. This function never reads or writes replay state. */
export const verifyAuthorizeProofBundleForAudit = async (
  rawBundle: Uint8Array,
  trust: SigilAuthorizeTrustV1,
  options: AuditAuthorizeProofOptions
): Promise<AuditAuthorizeProof> => {
  if (!(options.verificationTime instanceof Date) || !Number.isFinite(options.verificationTime.getTime())) {
    fail(AuthorizeVerificationErrorCode.AUDIT_TIME_INVALID, "audit verification time must be a valid Date");
  }
  if (options.verificationTime.getTime() > Date.now()) {
    fail(AuthorizeVerificationErrorCode.AUDIT_TIME_INVALID, "audit verification time must not be in the future");
  }
  const verificationTime = Math.floor(options.verificationTime.getTime() / 1000);
  const { common } = await verifyBase(rawBundle, trust, verificationTime, "audit");
  return {
    ...common,
    mode: "audit",
    verificationTime,
    expiredAtVerification: verificationTime >= common.expiresAt,
  };
};
