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
    iat?: number;
    policyHash: string;
    scope?: string;
    capabilities?: string[];
    execution_grant?: ExecutionGrantClaim;
    [key: string]: unknown;
  };
  intent: Intent;
}
