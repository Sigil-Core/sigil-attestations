export interface Intent {
  action: string;
  targetAddress: string;
  amount?: string;
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
    [key: string]: unknown;
  };
  intent: Intent;
}
