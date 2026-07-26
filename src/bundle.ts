import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createPublicKey, verify as verifySignature } from "node:crypto";
import { decodeProtectedHeader } from "jose";
import {
  canonicalizePolicyObject,
  hashPolicy,
  parsePolicyMarkdown,
  splitSignatureBlock,
} from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";
import { InvalidPayloadError, InvalidSignatureError } from "./errors.js";
import { verifyProvingGroundAttestation } from "./proving-ground.js";
import { assertTrustedBundleKeys, assertTrustedInformationalPqcKey, validateTrustManifest } from "./trust.js";
import type { VerifyBundleOptions, VerifyBundleResult } from "./types.js";

const requiredFiles = [
  "warranty.md",
  "operator-public-key.json",
  "attestation.jwt",
  "request.json",
  "response.json",
  "jwks.json",
  "pqc-keys.json",
  "policy.canonical.json",
  "VERIFY.md",
] as const;

export const CANONICAL_POLICY_ENVELOPE_SCHEMA = "sigil-policy-canonical/v1";
export const CANONICALIZER_VERSION = "@sigilcore/warrant-core@0.1.1";

const readUtf8 = async (bundlePath: string, name: string): Promise<string> => {
  try {
    return await readFile(join(bundlePath, name), "utf8");
  } catch {
    throw new InvalidPayloadError(`Proof bundle is missing ${name}`);
  }
};

const parseJson = (text: string, name: string): Record<string, unknown> => {
  try {
    const parsed = JSON.parse(text);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new InvalidPayloadError(`${name} must contain a JSON object`);
  }
};

const parseCanonicalPolicyEnvelope = (value: Record<string, unknown>): Record<string, unknown> => {
  if (value.schema !== CANONICAL_POLICY_ENVELOPE_SCHEMA || value.canonicalizer !== CANONICALIZER_VERSION) {
    throw new InvalidPayloadError("policy.canonical.json has an unsupported canonicalizer envelope");
  }
  if (typeof value.policy !== "object" || value.policy === null || Array.isArray(value.policy)) {
    throw new InvalidPayloadError("policy.canonical.json must contain a canonical policy object");
  }
  return value.policy as Record<string, unknown>;
};

const verifyOperatorSignature = (warranty: string, operatorKey: Record<string, unknown>): void => {
  const { unsigned, signature } = splitSignatureBlock(warranty);
  if (!signature) throw new InvalidPayloadError("warranty.md does not contain an operator signature");
  if (operatorKey.kty !== "OKP" || operatorKey.crv !== "Ed25519" || typeof operatorKey.x !== "string") {
    throw new InvalidPayloadError("operator-public-key.json must be an Ed25519 JWK");
  }
  let valid = false;
  try {
    valid = verifySignature(
      null,
      Buffer.from(unsigned, "utf8"),
      createPublicKey({ key: operatorKey, format: "jwk" }),
      Buffer.from(signature, "base64url")
    );
  } catch {
    throw new InvalidSignatureError("Operator public key or signature is invalid");
  }
  if (!valid) throw new InvalidSignatureError("Operator signature verification failed");
};

/**
 * Verifies an unpacked proof bundle. The caller supplies trust separately; this
 * function intentionally never reads a trust file from the bundle directory.
 */
export const verifyProofBundle = async (options: VerifyBundleOptions): Promise<VerifyBundleResult> => {
  const now = options.now ?? new Date();
  const trust = validateTrustManifest(options.trust, now);
  await Promise.all(requiredFiles.map((name) => readUtf8(options.bundlePath, name)));
  const [warranty, operatorText, jwt, requestText, responseText, jwksText, pqcKeysText, canonicalText] = await Promise.all([
    readUtf8(options.bundlePath, "warranty.md"),
    readUtf8(options.bundlePath, "operator-public-key.json"),
    readUtf8(options.bundlePath, "attestation.jwt"),
    readUtf8(options.bundlePath, "request.json"),
    readUtf8(options.bundlePath, "response.json"),
    readUtf8(options.bundlePath, "jwks.json"),
    readUtf8(options.bundlePath, "pqc-keys.json"),
    readUtf8(options.bundlePath, "policy.canonical.json"),
  ]);
  const operatorKey = parseJson(operatorText, "operator-public-key.json");
  const request = parseJson(requestText, "request.json");
  const response = parseJson(responseText, "response.json");
  const jwks = parseJson(jwksText, "jwks.json");
  const pqcKeys = parseJson(pqcKeysText, "pqc-keys.json");
  const suppliedCanonical = parseCanonicalPolicyEnvelope(parseJson(canonicalText, "policy.canonical.json"));
  if (!("intent" in request) || typeof request.txCommit !== "string") {
    throw new InvalidPayloadError("request.json must contain intent and txCommit");
  }
  if (response.intent_attestation !== jwt.trim()) {
    throw new InvalidPayloadError("response.json intent_attestation does not match attestation.jwt");
  }
  const header = decodeProtectedHeader(jwt.trim());
  if (typeof header.kid !== "string") throw new InvalidPayloadError("attestation JWT header must contain kid");
  await assertTrustedBundleKeys(trust, jwks, operatorKey, header.kid);
  await assertTrustedInformationalPqcKey(trust, pqcKeys);
  verifyOperatorSignature(warranty, operatorKey);
  const parsedPolicy = parsePolicyMarkdown(warranty);
  if (canonicalizePolicyObject(parsedPolicy) !== canonicalizePolicyObject(suppliedCanonical)) {
    throw new InvalidPayloadError("policy.canonical.json is not derived from warranty.md");
  }
  const derivedPolicyHash = await hashPolicy(createNodeCryptoAdapter(), parsedPolicy);
  const suppliedCanonicalHash = await hashPolicy(createNodeCryptoAdapter(), suppliedCanonical as Parameters<typeof hashPolicy>[1]);
  if (derivedPolicyHash !== suppliedCanonicalHash) {
    throw new InvalidPayloadError("policy.canonical.json hash does not match warranty.md");
  }
  const attestation = await verifyProvingGroundAttestation(jwt.trim(), {
    trust,
    jwks,
    request: { intent: request.intent, txCommit: request.txCommit },
    mode: options.mode,
    now,
  });
  if (derivedPolicyHash !== attestation.claims.policyHash) {
    throw new InvalidPayloadError("Derived policyHash does not match the attestation");
  }
  return { ...attestation, operatorSignatureValid: true, derivedPolicyHash };
};
