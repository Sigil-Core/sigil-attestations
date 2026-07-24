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

const isIntent = (value: unknown): value is Intent => {
  if (typeof value !== "object" || value === null) return false;
  const obj = value as Record<string, unknown>;
  if (typeof obj.action !== "string") return false;
  if (typeof obj.targetAddress !== "string") return false;
  if (obj.amount !== undefined && typeof obj.amount !== "string") return false;
  return true;
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

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

const validateBoundExecutionGrant = (
  value: unknown,
  policyHash: string,
  capabilities: string[] | undefined
): ExecutionGrantClaim | undefined => {
  if (value === undefined) return undefined;
  if (!isExecutionGrant(value)) {
    throw new InvalidPayloadError("execution_grant claim is malformed");
  }
  if (capabilities === undefined || capabilities.length === 0) {
    throw new InvalidPayloadError(
      "execution_grant requires at least one capability"
    );
  }
  if (value.policy_hash !== policyHash) {
    throw new InvalidPayloadError(
      "execution_grant policy_hash does not match policyHash"
    );
  }
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

const throwVerificationError = (error: unknown): never => {
  if (error instanceof SigilVerificationError) throw error;
  const message = error instanceof Error ? error.message : String(error);
  const code = (error as { code?: string }).code;

  if (code === "ERR_JWT_EXPIRED") {
    throw new ExpiredAttestationError();
  }
  if (
    code === "ERR_JWT_CLAIM_VALIDATION_FAILED" &&
    message.toLowerCase().includes("iss")
  ) {
    throw new InvalidIssuerError();
  }
  const signatureCodes = new Set([
    "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
    "ERR_JWS_INVALID",
    "ERR_JWT_INVALID",
  ]);
  if (code !== undefined && signatureCodes.has(code)) {
    throw new InvalidSignatureError();
  }
  throw new SigilVerificationError(message);
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

  // Step 3: Validate intent
  if (!isIntent(payload.intent)) {
    throw new InvalidPayloadError(
      "Payload missing or invalid intent (requires action: string, targetAddress: string)"
    );
  }

  const policyClaims = validatePolicyClaims(payload);

  const iat = typeof payload.iat === "number" ? payload.iat : undefined;

  return {
    protectedHeader: {
      alg: protectedHeader.alg as string,
      ...(protectedHeader.kid !== undefined && {
        kid: protectedHeader.kid as string,
      }),
      ...protectedHeader,
    },
    claims: {
      iss: payload.iss as string,
      exp: payload.exp as number,
      ...(iat !== undefined && { iat }),
      policyHash: policyClaims.policyHash,
      ...(typeof payload.scope === "string" && { scope: payload.scope }),
      ...(policyClaims.capabilities !== undefined && {
        capabilities: policyClaims.capabilities,
      }),
      ...(policyClaims.executionGrant !== undefined && {
        execution_grant: policyClaims.executionGrant,
      }),
    },
    intent: payload.intent,
  };
};
