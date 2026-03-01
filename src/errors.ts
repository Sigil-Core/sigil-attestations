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
