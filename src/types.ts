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
  request: { intent: unknown; txCommit: string };
  jwks: unknown;
  mode?: VerificationMode;
  now?: Date;
}

export interface ProvingGroundVerificationResult {
  mode: VerificationMode;
  authorizationExpired: boolean;
  protectedHeader: Record<string, unknown>;
  claims: { iss: string; aud: string; exp: number; iat: number; kid: string; intentHash: string; policyHash: string };
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
