export { verifyIntentAttestation } from "./verify.js";
export {
  SigilVerificationError,
  InvalidAlgorithmError,
  InvalidIssuerError,
  ExpiredAttestationError,
  InvalidPayloadError,
  InvalidSignatureError,
} from "./errors.js";
export type {
  Intent,
  VerifiedAttestation,
  VerifyIntentAttestationOptions,
} from "./types.js";
