export class SigilVerificationError extends Error {
  code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = "SigilVerificationError";
    this.code = code;
  }
}

export class InvalidAlgorithmError extends SigilVerificationError {
  constructor(message = "JWT algorithm must be EdDSA") {
    super(message, "INVALID_ALGORITHM");
    this.name = "InvalidAlgorithmError";
  }
}

export class InvalidIssuerError extends SigilVerificationError {
  constructor(message = "JWT issuer is invalid") {
    super(message, "INVALID_ISSUER");
    this.name = "InvalidIssuerError";
  }
}

export class ExpiredAttestationError extends SigilVerificationError {
  constructor(message = "JWT has expired") {
    super(message, "EXPIRED_ATTESTATION");
    this.name = "ExpiredAttestationError";
  }
}

export class InvalidPayloadError extends SigilVerificationError {
  constructor(message = "JWT payload is invalid or missing intent") {
    super(message, "INVALID_PAYLOAD");
    this.name = "InvalidPayloadError";
  }
}

export class InvalidSignatureError extends SigilVerificationError {
  constructor(message = "JWT signature verification failed") {
    super(message, "INVALID_SIGNATURE");
    this.name = "InvalidSignatureError";
  }
}

/** Stable public failures for the sigil-sign-authorize-v1 profile. */
export enum AuthorizeVerificationErrorCode {
  BUNDLE_ENCODING = "ERR_BUNDLE_ENCODING",
  BUNDLE_TOO_LARGE = "ERR_BUNDLE_TOO_LARGE",
  BUNDLE_SCHEMA = "ERR_BUNDLE_SCHEMA",
  PROFILE_UNKNOWN = "ERR_PROFILE_UNKNOWN",
  TRUST_REFERENCE_MISMATCH = "ERR_TRUST_REFERENCE_MISMATCH",
  KID_UNKNOWN = "ERR_KID_UNKNOWN",
  KID_MISMATCH = "ERR_KID_MISMATCH",
  ALG_UNSUPPORTED = "ERR_ALG_UNSUPPORTED",
  SIGNATURE = "ERR_SIGNATURE",
  ISSUER = "ERR_ISSUER",
  AUDIENCE = "ERR_AUDIENCE",
  CLAIM_MISMATCH = "ERR_CLAIM_MISMATCH",
  LIFETIME = "ERR_LIFETIME",
  EXPIRED = "ERR_EXPIRED",
  IAT_FUTURE = "ERR_IAT_FUTURE",
  TRUST_WINDOW = "ERR_TRUST_WINDOW",
  TRUST_REVOKED = "ERR_TRUST_REVOKED",
  AUDIT_TIME_INVALID = "ERR_AUDIT_TIME_INVALID",
  COMMIT_MISMATCH = "ERR_COMMIT_MISMATCH",
  INTENT_HASH_MISMATCH = "ERR_INTENT_HASH_MISMATCH",
  POLICY_PARSE = "ERR_POLICY_PARSE",
  POLICY_HASH_MISMATCH = "ERR_POLICY_HASH_MISMATCH",
  POLICY_TOO_LARGE = "ERR_POLICY_TOO_LARGE",
  REPLAY_DENIED = "ERR_REPLAY_DENIED",
  REPLAY_UNAVAILABLE = "ERR_REPLAY_UNAVAILABLE",
}

export class AuthorizeVerificationError extends Error {
  constructor(
    public readonly code: AuthorizeVerificationErrorCode,
    message: string
  ) {
    super(message);
    this.name = "AuthorizeVerificationError";
  }
}
