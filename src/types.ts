export interface Intent {
  action: string;
  targetAddress: string;
  amount?: string;
}

export interface VerifyIntentAttestationOptions {
  trustedIssuers?: string | readonly string[];
}

export interface ExecutionGrantClaim {
  policy_hash: string;
  manifest_sha256: string;
  shim_id: string;
  executor_id: string;
  adapter: string;
  adapter_version: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  repository_id?: string;
}

export interface VerifiedAttestation {
  protectedHeader: {
    alg: string;
    kid?: string;
    [key: string]: unknown;
  };
  claims: {
    iss: string;
    exp: number;
    iat: number;
    policyHash: string;
    scope?: string;
    capabilities?: string[];
    execution_grant?: ExecutionGrantClaim;
    [key: string]: unknown;
  };
  intent: Intent;
}

export type VerificationMode = "execution" | "audit";

export interface TrustAttestationKey {
  kid: string;
  jwkThumbprint: string;
}

export interface TrustPqcKey {
  kid: string;
  fingerprint: string;
}

export interface SigilTrustManifestV1 {
  schema: "sigil-trust/v1";
  issuer: string;
  audience: "sigil-sign";
  verifiedAlgorithms: ["EdDSA", ...string[]];
  informationalAlgorithms: string[];
  notBefore: string;
  notAfter: string;
  reviewAfter: string;
  revokedAt: string | null;
  attestationKeys: TrustAttestationKey[];
  operatorKey: { fingerprint: string };
  pqcKey: TrustPqcKey;
}

export interface ProvingGroundVerificationOptions {
  trust: SigilTrustManifestV1;
  request: { intent: unknown; txCommit: string; chainId?: number };
  jwks: unknown;
  mode?: VerificationMode;
  now?: Date;
}

export interface ProvingGroundVerificationResult {
  mode: VerificationMode;
  authorizationExpired: boolean;
  protectedHeader: Record<string, unknown>;
  claims: {
    iss: string;
    aud: string;
    exp: number;
    iat: number;
    kid: string;
    intentHash: string;
    policyHash: string;
    chainId?: number;
  };
  commitment: { txCommit: string; intentHash: string };
}

export interface VerifyBundleOptions {
  bundlePath: string;
  trust: SigilTrustManifestV1;
  mode?: VerificationMode;
  now?: Date;
}

export interface VerifyBundleResult extends ProvingGroundVerificationResult {
  operatorSignatureValid: true;
  derivedPolicyHash: string;
}

/** JSON accepted inside the exact request.intent commitment boundary. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/**
 * The independently acquired trust configuration for sigil-sign-authorize-v1.
 * Unlike the legacy sigil-trust/v1 document, this configuration carries the
 * actual public JWK used for signature verification. A bundle never carries
 * an authority-bearing key.
 */
export interface SigilAuthorizeTrustV1 {
  schema: "sigil-authorize-trust/v1";
  manifest_sha256: string;
  issuer: string;
  audience: string;
  keys: readonly AuthorizeTrustKey[];
}

export interface AuthorizeTrustKey {
  kid: string;
  jwk: {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
    alg?: "EdDSA";
  };
  /** Unix seconds, inclusive. */
  not_before: number;
  /** Unix seconds, exclusive. */
  not_after: number;
  /** Unix seconds, exclusive at issuance and verification when present. */
  revoked_at?: number;
}

export interface SigilAuthorizeProofBundleV1 {
  bundle_version: "sigil-authorize-proof/v1";
  verification_profile: "sigil-sign-authorize-v1";
  token: string;
  request: {
    agentId: string;
    framework: string;
    chainId?: number;
    txCommit: string;
    intent: JsonValue;
  };
  policy: { warranty_md: string };
  trust_reference: {
    manifest_sha256: string;
    issuer: string;
    audience: string;
  };
}

/** A conforming store must implement consumeIfUnused as one atomic CAS. */
export type AuthorizeReplayConsumeResult =
  | { status: "consumed" }
  | { status: "replayed" }
  | { status: "clock_drift" };

/**
 * A conforming store performs a single atomic compare-and-consume operation.
 * Before writing the replay id, it compares its authoritative clock with
 * verificationTimeUnixSeconds and returns clock_drift without consuming when
 * the difference exceeds maxClockDriftSeconds.
 */
export interface AuthorizeReplayStore {
  consumeIfUnused(
    replayId: string,
    retainUntilUnixSeconds: number,
    verificationTimeUnixSeconds: number,
    maxClockDriftSeconds: number
  ): Promise<AuthorizeReplayConsumeResult>;
}

declare const executionAuthorizeProofBrand: unique symbol;

export interface AuthorizeProofCommon {
  profile: "sigil-sign-authorize-v1";
  issuer: string;
  kid: string;
  txCommit: string;
  intentHash: string;
  policyHash: string;
  issuedAt: number;
  expiresAt: number;
}

/** This nominal type is the only successful execution-authorization result. */
export interface ExecutionAuthorizeProof extends AuthorizeProofCommon {
  mode: "execution";
  readonly [executionAuthorizeProofBrand]: true;
}

/** Historical evidence is structurally unable to substitute for execution authority. */
export interface AuditAuthorizeProof extends AuthorizeProofCommon {
  mode: "audit";
  verificationTime: number;
  expiredAtVerification: boolean;
}

export interface AuditAuthorizeProofOptions {
  verificationTime: Date;
}
