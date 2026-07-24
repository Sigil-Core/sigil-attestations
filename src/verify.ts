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

function normalizeTrustedIssuers(
  trustedIssuers: VerifyIntentAttestationOptions["trustedIssuers"]
): string[] {
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
}

function isIntent(value: unknown): value is Intent {
  if (typeof value !== "object" || value === null) return false;
  const obj = value as Record<string, unknown>;
  if (typeof obj.action !== "string") return false;
  if (typeof obj.targetAddress !== "string") return false;
  if (obj.amount !== undefined && typeof obj.amount !== "string") return false;
  return true;
}

function isExecutionGrant(value: unknown): value is ExecutionGrantClaim {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  const strings = ["policy_hash", "manifest_sha256", "shim_id", "executor_id", "adapter", "adapter_version", "nonce"];
  if (strings.some((key) => typeof candidate[key] !== "string" || candidate[key] === "")) return false;
  if (!Number.isSafeInteger(candidate.issued_at) || !Number.isSafeInteger(candidate.expires_at)) return false;
  const issuedAt = candidate.issued_at as number;
  const expiresAt = candidate.expires_at as number;
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 300) return false;
  return candidate.repository_id === undefined || typeof candidate.repository_id === "string";
}

export async function verifyIntentAttestation(
  jwt: string,
  jwks: unknown,
  options: VerifyIntentAttestationOptions = {}
): Promise<VerifiedAttestation> {
  const trustedIssuers = normalizeTrustedIssuers(options.trustedIssuers);

  // Step 1: Enforce EdDSA before signature verification
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

  // Step 2: Verify signature + standard claims
  let payload: Record<string, unknown>;
  let protectedHeader: Record<string, unknown>;

  try {
    const keySet = createLocalJWKSet(jwks as Parameters<typeof createLocalJWKSet>[0]);
    const result = await jwtVerify(jwt, keySet, {
      algorithms: ["EdDSA"],
      issuer: trustedIssuers,
    });
    payload = result.payload as Record<string, unknown>;
    protectedHeader = result.protectedHeader as Record<string, unknown>;
  } catch (err: unknown) {
    if (err instanceof SigilVerificationError) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    const code = (err as { code?: string }).code;

    if (code === "ERR_JWT_EXPIRED") {
      throw new ExpiredAttestationError();
    }
    if (
      code === "ERR_JWT_CLAIM_VALIDATION_FAILED" &&
      msg.toLowerCase().includes("iss")
    ) {
      throw new InvalidIssuerError();
    }
    if (
      code === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" ||
      code === "ERR_JWS_INVALID" ||
      code === "ERR_JWT_INVALID"
    ) {
      throw new InvalidSignatureError();
    }
    throw new SigilVerificationError(msg);
  }

  // Step 3: Validate intent
  if (!isIntent(payload.intent)) {
    throw new InvalidPayloadError(
      "Payload missing or invalid intent (requires action: string, targetAddress: string)"
    );
  }

  if (typeof payload.policyHash !== "string" || payload.policyHash.length === 0) {
    throw new InvalidPayloadError("Payload missing or invalid policyHash");
  }

  if (payload.execution_grant !== undefined && !isExecutionGrant(payload.execution_grant)) {
    throw new InvalidPayloadError("execution_grant claim is malformed");
  }
  if (isExecutionGrant(payload.execution_grant) && payload.execution_grant.policy_hash !== payload.policyHash) {
    throw new InvalidPayloadError("execution_grant policy_hash does not match policyHash");
  }
  if (isExecutionGrant(payload.execution_grant)) {
    const now = Math.floor(Date.now() / 1000);
    if (
      payload.execution_grant.expires_at <= now ||
      payload.execution_grant.issued_at > now + CLOCK_TOLERANCE_SECONDS
    ) {
      throw new InvalidPayloadError("execution_grant is expired or not yet valid");
    }
  }
  if (payload.capabilities !== undefined && (!Array.isArray(payload.capabilities) || payload.capabilities.some((capability) => typeof capability !== "string" || capability.length === 0))) {
    throw new InvalidPayloadError("capabilities claim must be a list of non-empty strings");
  }

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
      policyHash: payload.policyHash,
      ...(typeof payload.scope === "string" && { scope: payload.scope }),
      ...(Array.isArray(payload.capabilities) && { capabilities: payload.capabilities as string[] }),
      ...(isExecutionGrant(payload.execution_grant) && { execution_grant: payload.execution_grant }),
    },
    intent: payload.intent,
  };
}
