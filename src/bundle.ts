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
/**
 * Identifier a new proof-bundle envelope must carry. It names canonicalization
 * behavior, not the installed npm version, but it must name a release whose
 * behavior this package can actually reproduce, so it tracks the pin whenever
 * the pin widens what can be canonicalized.
 */
export const CANONICALIZER_VERSION = "@sigilcore/warrant-core@0.4.0";

/**
 * Verification-only compatibility for envelopes already issued by earlier
 * pinned verifiers, newest first. New emitters must use CANONICALIZER_VERSION.
 *
 * An identifier is retained here only while its canonicalization output is
 * proven byte-identical to CANONICALIZER_VERSION for every policy both
 * releases accept. That holds for 0.2.1 and 0.2.3: measured across the shipped
 * sigil-open-framework examples, the sigil-sign fixtures, and this package's
 * own test Warrant, all three releases produce the same canonical bytes and
 * the same policy hash. 0.4.0 differs only by accepting Policy 2.2 and 2.3,
 * which the earlier releases reject outright rather than canonicalize
 * differently.
 *
 * Identifiers this package once pinned but never shipped as an envelope value
 * (0.1.1, 0.2.0) stay rejected, as do releases that were never an identifier
 * at all (0.2.2, 0.2.4, 0.3.0). Acceptance is an allowlist of values a bundle
 * may legitimately carry, not a compatibility claim about every release.
 */
export const HISTORICAL_CANONICALIZER_VERSIONS = [
  "@sigilcore/warrant-core@0.2.3",
  "@sigilcore/warrant-core@0.2.1",
] as const;

const acceptedCanonicalizerVersions = new Set<string>([
  CANONICALIZER_VERSION,
  ...HISTORICAL_CANONICALIZER_VERSIONS,
]);

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

// skipcq: JS-R1005 - This centralized envelope guard preserves the canonical policy boundary before any signature or hash verification.
const parseCanonicalPolicyEnvelope = (value: Record<string, unknown>): Record<string, unknown> => {
  if (
    value.schema !== CANONICAL_POLICY_ENVELOPE_SCHEMA ||
    typeof value.canonicalizer !== "string" ||
    !acceptedCanonicalizerVersions.has(value.canonicalizer)
  ) {
    throw new InvalidPayloadError("policy.canonical.json has an unsupported canonicalizer envelope");
  }
  if (typeof value.policy !== "object" || value.policy === null || Array.isArray(value.policy)) {
    throw new InvalidPayloadError("policy.canonical.json must contain a canonical policy object");
  }
  return value.policy as Record<string, unknown>;
};

// skipcq: JS-R1005 - This ordered fail-closed signature gate keeps all warranty key and signature checks auditable in one boundary.
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
// skipcq: JS-R1005 - This offline verifier intentionally sequences trust, bundle, signature, policy, and commitment checks fail-closed.
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
  if (response.intent_attestation !== jwt) {
    throw new InvalidPayloadError("response.json intent_attestation does not match attestation.jwt");
  }
  const header = decodeProtectedHeader(jwt);
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
  const attestation = await verifyProvingGroundAttestation(jwt, {
    trust,
    jwks,
    request: {
      intent: request.intent,
      txCommit: request.txCommit,
      ...(Object.prototype.hasOwnProperty.call(request, "chainId")
        ? { chainId: request.chainId as number }
        : {}),
    },
    mode: options.mode,
    now,
  });
  if (derivedPolicyHash !== attestation.claims.policyHash) {
    throw new InvalidPayloadError("Derived policyHash does not match the attestation");
  }
  return { ...attestation, operatorSignatureValid: true, derivedPolicyHash };
};
