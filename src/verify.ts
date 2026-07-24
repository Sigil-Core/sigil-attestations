import { decodeProtectedHeader, jwtVerify, createLocalJWKSet, type ProtectedHeaderParameters } from "jose";
import {
  InvalidAlgorithmError,
  InvalidIssuerError,
  ExpiredAttestationError,
  InvalidPayloadError,
  InvalidSignatureError,
  SigilVerificationError,
} from "./errors.js";
import type {
  Intent,
  ExecutionGrantClaim,
  VerifiedAttestation,
  VerifyIntentAttestationOptions,
} from "./types.js";

const DEFAULT_TRUSTED_ISSUERS = ["sigil-core"] as const;
const CLOCK_TOLERANCE_SECONDS = 5;
const RECEIPT_SCOPES = new Set(["rpc:write", "bundler:send"]);
const SIGNATURE_ERROR_CODES = new Set([
  "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
  "ERR_JWS_INVALID",
  "ERR_JWT_INVALID",
]);
const EXECUTION_GRANT_STRING_FIELDS = [
  "policy_hash",
  "manifest_sha256",
  "shim_id",
  "executor_id",
  "adapter",
  "adapter_version",
  "nonce",
] as const;

const normalizeTrustedIssuers = (
  trustedIssuers: VerifyIntentAttestationOptions["trustedIssuers"]
): string[] => {
  const issuerValues =
    trustedIssuers === undefined
      ? DEFAULT_TRUSTED_ISSUERS
      : typeof trustedIssuers === "string"
        ? [trustedIssuers]
        : trustedIssuers;
  const normalized = [...new Set(issuerValues.map((issuer) => issuer.trim()))]
    .filter((issuer) => issuer.length > 0);

  if (normalized.length === 0) {
    throw new InvalidIssuerError("At least one trusted issuer is required");
  }

  return normalized;
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

const isIntent = (value: unknown): value is Intent =>
  isRecord(value) &&
  typeof value.action === "string" &&
  typeof value.targetAddress === "string" &&
  (value.amount === undefined || typeof value.amount === "string");

const hasValidExecutionGrantStrings = (
  candidate: Record<string, unknown>
): boolean =>
  EXECUTION_GRANT_STRING_FIELDS.every((key) =>
    isNonEmptyString(candidate[key])
  );

const hasValidExecutionGrantTimestamps = (
  candidate: Record<string, unknown>
): boolean => {
  if (!Number.isSafeInteger(candidate.issued_at)) return false;
  if (!Number.isSafeInteger(candidate.expires_at)) return false;
  const issuedAt = candidate.issued_at as number;
  const expiresAt = candidate.expires_at as number;
  return expiresAt > issuedAt && expiresAt - issuedAt <= 300;
};

const hasValidRepositoryId = (candidate: Record<string, unknown>): boolean =>
  candidate.repository_id === undefined ||
  isNonEmptyString(candidate.repository_id);

const isExecutionGrant = (value: unknown): value is ExecutionGrantClaim => {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    hasValidExecutionGrantStrings(candidate) &&
    hasValidExecutionGrantTimestamps(candidate) &&
    hasValidRepositoryId(candidate)
  );
};

const validateExecutionGrantWindow = (grant: ExecutionGrantClaim): void => {
  const now = Math.floor(Date.now() / 1000);
  if (
    grant.expires_at <= now ||
    grant.issued_at > now + CLOCK_TOLERANCE_SECONDS
  ) {
    throw new InvalidPayloadError("execution_grant is expired or not yet valid");
  }
};

const validateTemporalClaims = (payload: Record<string, unknown>): void => {
  if (!Number.isSafeInteger(payload.exp)) {
    throw new InvalidPayloadError("Payload missing or invalid exp");
  }
  if (!Number.isSafeInteger(payload.iat)) {
    throw new InvalidPayloadError("Payload missing or invalid iat");
  }
  const now = Math.floor(Date.now() / 1000);
  if ((payload.iat as number) > now + CLOCK_TOLERANCE_SECONDS) {
    throw new InvalidPayloadError(
      "iat claim is beyond the five-second clock tolerance"
    );
  }
};

const validateCapabilities = (value: unknown): string[] | undefined => {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    value.some((capability) => !isNonEmptyString(capability))
  ) {
    throw new InvalidPayloadError(
      "capabilities claim must be a list of non-empty strings"
    );
  }
  return value;
};

const validateScope = (value: unknown): string | undefined => {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !RECEIPT_SCOPES.has(value)) {
    throw new InvalidPayloadError(
      "scope claim must be rpc:write or bundler:send"
    );
  }
  return value;
};

const requireExecutionGrantCapabilities = (
  capabilities: string[] | undefined
): void => {
  if (capabilities === undefined || capabilities.length === 0) {
    throw new InvalidPayloadError(
      "execution_grant requires at least one capability"
    );
  }
};

const requireExecutionGrantPolicyBinding = (
  grant: ExecutionGrantClaim,
  policyHash: string
): void => {
  if (grant.policy_hash !== policyHash) {
    throw new InvalidPayloadError(
      "execution_grant policy_hash does not match policyHash"
    );
  }
};

const validateBoundExecutionGrant = (
  value: unknown,
  policyHash: string,
  capabilities: string[] | undefined
): ExecutionGrantClaim | undefined => {
  if (value === undefined) return undefined;
  if (!isExecutionGrant(value)) {
    throw new InvalidPayloadError("execution_grant claim is malformed");
  }
  requireExecutionGrantCapabilities(capabilities);
  requireExecutionGrantPolicyBinding(value, policyHash);
  validateExecutionGrantWindow(value);
  return value;
};

const validatePolicyClaims = (
  payload: Record<string, unknown>
): {
  policyHash: string;
  capabilities?: string[];
  executionGrant?: ExecutionGrantClaim;
} => {
  if (!isNonEmptyString(payload.policyHash)) {
    throw new InvalidPayloadError("Payload missing or invalid policyHash");
  }
  const capabilities = validateCapabilities(payload.capabilities);
  const executionGrant = validateBoundExecutionGrant(
    payload.execution_grant,
    payload.policyHash,
    capabilities
  );
  return {
    policyHash: payload.policyHash,
    ...(capabilities !== undefined && { capabilities }),
    ...(executionGrant !== undefined && { executionGrant }),
  };
};

const decodeEdDsaHeader = async (
  jwt: string
): Promise<ProtectedHeaderParameters> => {
  let header: ProtectedHeaderParameters;
  try {
    header = await decodeProtectedHeader(jwt);
  } catch {
    throw new SigilVerificationError("Failed to decode JWT header");
  }
  if (header.alg !== "EdDSA") {
    throw new InvalidAlgorithmError(
      `Expected alg=EdDSA, got alg=${header.alg}`
    );
  }
  return header;
};

const isIssuerClaimError = (
  code: string | undefined,
  message: string
): boolean =>
  code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && /iss/i.test(message);

const getErrorMessage = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const getExactVerificationError = (
  code: string | undefined
): SigilVerificationError | undefined => {
  if (code === "ERR_JWT_EXPIRED") return new ExpiredAttestationError();
  if (code !== undefined && SIGNATURE_ERROR_CODES.has(code)) {
    return new InvalidSignatureError();
  }
  return undefined;
};

const createVerificationError = (error: unknown): SigilVerificationError => {
  if (error instanceof SigilVerificationError) return error;
  const message = getErrorMessage(error);
  const code = (error as { code?: string }).code;
  const exactError = getExactVerificationError(code);
  if (exactError !== undefined) return exactError;
  if (isIssuerClaimError(code, message)) {
    return new InvalidIssuerError();
  }
  return new SigilVerificationError(message);
};

const throwVerificationError = (error: unknown): never => {
  throw createVerificationError(error);
};

const validateIntent = (value: unknown): Intent => {
  if (!isIntent(value)) {
    throw new InvalidPayloadError(
      "Payload missing or invalid intent (requires action: string, targetAddress: string)"
    );
  }
  return value;
};

const buildProtectedHeader = (
  protectedHeader: Record<string, unknown>
): VerifiedAttestation["protectedHeader"] => ({
  alg: protectedHeader.alg as string,
  ...(protectedHeader.kid !== undefined && {
    kid: protectedHeader.kid as string,
  }),
  ...protectedHeader,
});

const buildVerifiedClaims = (
  payload: Record<string, unknown>,
  policyClaims: ReturnType<typeof validatePolicyClaims>
): VerifiedAttestation["claims"] => {
  const claims: VerifiedAttestation["claims"] = {
    iss: payload.iss as string,
    exp: payload.exp as number,
    iat: payload.iat as number,
    policyHash: policyClaims.policyHash,
  };
  const scope = validateScope(payload.scope);
  if (scope !== undefined) claims.scope = scope;
  if (policyClaims.capabilities !== undefined) {
    claims.capabilities = policyClaims.capabilities;
  }
  if (policyClaims.executionGrant !== undefined) {
    claims.execution_grant = policyClaims.executionGrant;
  }
  return claims;
};

const verifyJwt = async (
  jwt: string,
  jwks: unknown,
  trustedIssuers: string[]
): Promise<{
  payload: Record<string, unknown>;
  protectedHeader: Record<string, unknown>;
}> => {
  try {
    const keySet = createLocalJWKSet(
      jwks as Parameters<typeof createLocalJWKSet>[0]
    );
    const result = await jwtVerify(jwt, keySet, {
      algorithms: ["EdDSA"],
      issuer: trustedIssuers,
    });
    return {
      payload: result.payload as Record<string, unknown>,
      protectedHeader: result.protectedHeader as Record<string, unknown>,
    };
  } catch (error: unknown) {
    return throwVerificationError(error);
  }
};

export const verifyIntentAttestation = async (
  jwt: string,
  jwks: unknown,
  options: VerifyIntentAttestationOptions = {}
): Promise<VerifiedAttestation> => {
  const trustedIssuers = normalizeTrustedIssuers(options.trustedIssuers);

  // Step 1: Enforce EdDSA before signature verification
  await decodeEdDsaHeader(jwt);

  // Step 2: Verify signature + standard claims
  const { payload, protectedHeader } = await verifyJwt(
    jwt,
    jwks,
    trustedIssuers
  );
  validateTemporalClaims(payload);

  // Step 3: Validate intent
  const intent = validateIntent(payload.intent);
  const policyClaims = validatePolicyClaims(payload);

  return {
    protectedHeader: buildProtectedHeader(protectedHeader),
    claims: buildVerifiedClaims(payload, policyClaims),
    intent,
  };
};
