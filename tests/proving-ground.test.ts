import { createHash, sign as signBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { appendSignatureBlock, hashPgCommitV1, hashPolicy, parsePolicyMarkdown } from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";
import {
  canonicalizePolicyObject as canonicalizePolicyObjectFrom021,
  parsePolicyMarkdown as parsePolicyMarkdownFrom021,
} from "warrant-core-0-2-1-fixture";
import { verifyProvingGroundAttestation } from "../src/index.js";
import { verifyProofBundle } from "../src/node.js";
import {
  CANONICALIZER_VERSION,
  CANONICAL_POLICY_ENVELOPE_SCHEMA,
  HISTORICAL_CANONICALIZER_VERSION,
} from "../src/bundle.js";
import { fingerprintEd25519RawKey, fingerprintJwk, fingerprintPqcRawKey, validateTrustManifest } from "../src/trust.js";
import type { SigilTrustManifestV1, VerificationMode } from "../src/types.js";

const directories: string[] = [];
const NOW = new Date("2030-01-01T00:00:00Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const WARRANTY = "version: 2.1.0\n\n## tool_calls\nallowed: web_fetch\n";
const INTENT = { action: "web_fetch", url: "https://docs.sigilcore.com/getting-started", metadata: { job_type: "documentation" } };

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const PQC_KEY = { kty: "ML-DSA", alg: "ML-DSA-65", kid: "synthetic-pqc", publicKey: "AQIDBA", use: "sig" };

// skipcq: JS-R1005 - The fixture creates one cryptographically linked offline bundle so every negative test mutates a consistent baseline.
const makeArtifacts = async (overrides: { attestationPolicyHash?: string; audience?: string; payloadKid?: string; expiresAt?: number; warranty?: string; canonical?: unknown; jwks?: unknown; pqcKeys?: unknown; responseAttestation?: string; chainId?: number } = {}) => {
  const signer = await generateKeyPair("EdDSA");
  const operator = await generateKeyPair("EdDSA");
  const signerJwk = await exportJWK(signer.publicKey);
  const operatorJwk = await exportJWK(operator.publicKey) as Record<string, unknown>;
  const kid = "synthetic-signer";
  const policy = parsePolicyMarkdown(overrides.warranty ?? WARRANTY);
  const policyHash = await hashPolicy(createNodeCryptoAdapter(), policy);
  const txCommit = await hashPgCommitV1(createNodeCryptoAdapter(), INTENT);
  const intentHash = createHash("sha256").update(txCommit, "utf8").digest("hex");
  const jwtClaims: Record<string, unknown> = {
    aud: overrides.audience ?? "sigil-sign", kid: overrides.payloadKid ?? kid, intentHash, policyHash: overrides.attestationPolicyHash ?? policyHash,
    agentId: "synthetic-agent", framework: "synthetic", provenance: "agent",
  };
  if (overrides.chainId !== undefined) jwtClaims.chainId = overrides.chainId;
  const jwt = await new SignJWT(jwtClaims)
    .setProtectedHeader({ alg: "EdDSA", kid })
    .setIssuer("sigil-core")
    .setIssuedAt(NOW_SECONDS - 10)
    .setExpirationTime(overrides.expiresAt ?? NOW_SECONDS + 50)
    .sign(signer.privateKey);
  const unsigned = overrides.warranty ?? WARRANTY;
  const signature = signBytes(null, Buffer.from(unsigned.trimEnd(), "utf8"), operator.privateKey).toString("base64url");
  const warranty = appendSignatureBlock(unsigned, signature);
  const trust: SigilTrustManifestV1 = {
    schema: "sigil-trust/v1", issuer: "sigil-core", audience: "sigil-sign",
    verifiedAlgorithms: ["EdDSA"], informationalAlgorithms: ["ML-DSA-65"],
    notBefore: "2029-01-01T00:00:00Z", notAfter: "2031-01-01T00:00:00Z", reviewAfter: "2030-06-01T00:00:00Z", revokedAt: null,
    attestationKeys: [{ kid, jwkThumbprint: await fingerprintJwk(signerJwk) }],
    operatorKey: { fingerprint: await fingerprintEd25519RawKey(operatorJwk.x as string) },
    pqcKey: { kid: PQC_KEY.kid, fingerprint: await fingerprintPqcRawKey(PQC_KEY.publicKey) },
  };
  const directory = await mkdtemp(join(tmpdir(), "sigil-proof-"));
  directories.push(directory);
  await Promise.all([
    writeFile(join(directory, "warranty.md"), warranty),
    writeFile(join(directory, "operator-public-key.json"), JSON.stringify(operatorJwk)),
    writeFile(join(directory, "attestation.jwt"), jwt),
    writeFile(join(directory, "request.json"), JSON.stringify({
      intent: INTENT,
      txCommit,
      ...(overrides.chainId === undefined ? {} : { chainId: overrides.chainId }),
    })),
    writeFile(join(directory, "response.json"), JSON.stringify({ intent_attestation: overrides.responseAttestation ?? jwt })),
    writeFile(join(directory, "jwks.json"), JSON.stringify(overrides.jwks ?? { keys: [{ ...signerJwk, kid, alg: "EdDSA", use: "sig" }] })),
    writeFile(join(directory, "pqc-keys.json"), JSON.stringify(overrides.pqcKeys ?? { keys: [PQC_KEY] })),
    writeFile(join(directory, "policy.canonical.json"), JSON.stringify(overrides.canonical ?? {
      schema: CANONICAL_POLICY_ENVELOPE_SCHEMA,
      canonicalizer: CANONICALIZER_VERSION,
      policy,
    })),
    writeFile(join(directory, "VERIFY.md"), "Synthetic verifier instructions only.\n"),
  ]);
  return { directory, trust, jwt, privateKey: signer.privateKey, jwks: { keys: [{ ...signerJwk, kid, alg: "EdDSA", use: "sig" }] }, txCommit };
};

describe("Proving Ground verifier profile", () => {
  it("proves the complete synthetic offline chain", async () => {
    const artifact = await makeArtifacts();
    const result = await verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW });
    expect(result.operatorSignatureValid).toBe(true);
    expect(result.authorizationExpired).toBe(false);
    expect(result.commitment.txCommit).toBe(artifact.txCommit);
    expect(result.claims.chainId).toBeUndefined();
  });

  it("proves the signed chain while leaving pg-commit-v1 bound only to intent", async () => {
    const artifact = await makeArtifacts({ chainId: 1 });
    const result = await verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW });
    expect(result.claims.chainId).toBe(1);
    expect(result.commitment.txCommit).toBe(artifact.txCommit);
  });

  it("keeps execution expiry strict while audit mode verifies historical proof", async () => {
    const artifact = await makeArtifacts({ expiresAt: NOW_SECONDS - 1 });
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW })).rejects.toThrow("JWT has expired");
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, mode: "audit", now: NOW })).resolves.toMatchObject({ authorizationExpired: true });
  });

  it("rejects invalid modes and clocks before temporal checks", async () => {
    const expired = await makeArtifacts({ expiresAt: NOW_SECONDS - 1 });
    const request = { intent: INTENT, txCommit: expired.txCommit };
    await expect(verifyProvingGroundAttestation(expired.jwt, {
      trust: expired.trust,
      jwks: expired.jwks,
      request,
      mode: "unsupported" as VerificationMode,
      now: NOW,
    })).rejects.toThrow("mode must be execution or audit");
    await expect(verifyProvingGroundAttestation(expired.jwt, {
      trust: expired.trust,
      jwks: expired.jwks,
      request,
      now: new Date("invalid"),
    })).rejects.toThrow("now must be a valid Date");
  });

  it.each([
    ["a non-string value", ["EdDSA", null]],
    ["an array without EdDSA first", ["RS256", "EdDSA"]],
  ])("rejects verifiedAlgorithms with %s", async (_label, verifiedAlgorithms) => {
    const artifact = await makeArtifacts();
    const trust = { ...artifact.trust, verifiedAlgorithms };
    expect(() => validateTrustManifest(trust, NOW)).toThrow("verifiedAlgorithms must begin with EdDSA and contain only strings");
  });

  it("rejects malformed JWTs and required claims before commitment checks", async () => {
    const artifact = await makeArtifacts();
    const request = { intent: INTENT, txCommit: artifact.txCommit };
    await expect(verifyProvingGroundAttestation("not-a-jwt", {
      trust: artifact.trust, jwks: artifact.jwks, request, now: NOW,
    })).rejects.toThrow("compact base64url serialization");
    const withoutHeaderKid = await new SignJWT(decodeJwt(artifact.jwt))
      .setProtectedHeader({ alg: "EdDSA" })
      .sign(artifact.privateKey);
    await expect(verifyProvingGroundAttestation(withoutHeaderKid, {
      trust: artifact.trust, jwks: artifact.jwks, request, now: NOW,
    })).rejects.toThrow("JWT header kid must be a non-empty string");
    const omitRequiredClaim = {
      kid: ({ kid: _kid, ...payload }: Record<string, unknown>) => payload,
      exp: ({ exp: _exp, ...payload }: Record<string, unknown>) => payload,
      iat: ({ iat: _iat, ...payload }: Record<string, unknown>) => payload,
      intentHash: ({ intentHash: _intentHash, ...payload }: Record<string, unknown>) => payload,
    };
    for (const omitClaim of Object.values(omitRequiredClaim)) {
      const payload = omitClaim(decodeJwt(artifact.jwt) as Record<string, unknown>);
      const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: "EdDSA", kid: "synthetic-signer" })
        .sign(artifact.privateKey);
      await expect(verifyProvingGroundAttestation(jwt, {
        trust: artifact.trust, jwks: artifact.jwks, request, now: NOW,
      })).rejects.toThrow();
    }
  });

  it("rejects invalid standalone trust clocks and timestamps before bundle parsing", async () => {
    const artifact = await makeArtifacts();
    expect(() => validateTrustManifest(artifact.trust, new Date("invalid"))).toThrow("validation time must be a valid Date");
    expect(() => validateTrustManifest({ ...artifact.trust, notBefore: "2029-02-29T00:00:00Z" }, NOW)).toThrow("notBefore must be an ISO timestamp");
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: {} as SigilTrustManifestV1, now: NOW })).rejects.toThrow("Unsupported trust manifest schema");
  });

  it("rejects response attestations that differ from the exact JWT file bytes", async () => {
    const artifact = await makeArtifacts();
    await writeFile(join(artifact.directory, "attestation.jwt"), ` ${artifact.jwt}\n`);
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW })).rejects.toThrow("response.json intent_attestation does not match attestation.jwt");
  });

  it("rejects a tampered request intent", async () => {
    const artifact = await makeArtifacts();
    await writeFile(join(artifact.directory, "request.json"), JSON.stringify({ intent: { ...INTENT, action: "email.send" }, txCommit: artifact.txCommit }));
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW })).rejects.toThrow("does not match pg-commit-v1 intent");
  });

  it("rejects a request that differs only by chain", async () => {
    const artifact = await makeArtifacts({ chainId: 1 });
    await writeFile(join(artifact.directory, "request.json"), JSON.stringify({
      intent: INTENT,
      txCommit: artifact.txCommit,
      chainId: 8453,
    }));
    await expect(verifyProofBundle({
      bundlePath: artifact.directory,
      trust: artifact.trust,
      now: NOW,
    })).rejects.toThrow("JWT chainId must exactly match request chainId");
  });

  it.each([
    ["JWT chainId", { signed: 0, requested: 0 }, "JWT chainId must be a positive safe integer"],
    ["JWT chainId", { signed: Number.MAX_SAFE_INTEGER + 1, requested: 1 }, "JWT chainId must be a positive safe integer"],
    ["request chainId", { signed: 1, requested: -1 }, "request chainId must be a positive safe integer"],
    ["request chainId", { signed: 1, requested: 1.5 }, "request chainId must be a positive safe integer"],
    ["missing request chainId", { signed: 1, requested: undefined }, "JWT chainId must exactly match request chainId"],
    ["missing JWT chainId", { signed: undefined, requested: 1 }, "JWT chainId must exactly match request chainId"],
  ])("rejects invalid or unmatched %s", async (_label, chainIds, message) => {
    const artifact = await makeArtifacts({ chainId: chainIds.signed });
    const request: Record<string, unknown> = { intent: INTENT, txCommit: artifact.txCommit };
    if (chainIds.requested !== undefined) request.chainId = chainIds.requested;
    await writeFile(join(artifact.directory, "request.json"), JSON.stringify(request));
    await expect(verifyProofBundle({
      bundlePath: artifact.directory,
      trust: artifact.trust,
      now: NOW,
    })).rejects.toThrow(message);
  });

  it("rejects a changed commitment, policy hash, or JWT signature", async () => {
    const commitment = await makeArtifacts();
    await writeFile(join(commitment.directory, "request.json"), JSON.stringify({ intent: INTENT, txCommit: "a".repeat(64) }));
    await expect(verifyProofBundle({ bundlePath: commitment.directory, trust: commitment.trust, now: NOW })).rejects.toThrow("does not match pg-commit-v1 intent");
    const policy = await makeArtifacts({ attestationPolicyHash: "b".repeat(64) });
    await expect(verifyProofBundle({ bundlePath: policy.directory, trust: policy.trust, now: NOW })).rejects.toThrow("Derived policyHash does not match");
    const signature = await makeArtifacts();
    const [header, payload, encodedSignature] = signature.jwt.split(".");
    const changedSignature = `${encodedSignature[0] === "A" ? "B" : "A"}${encodedSignature.slice(1)}`;
    await writeFile(join(signature.directory, "attestation.jwt"), `${header}.${payload}.${changedSignature}`);
    await expect(verifyProofBundle({ bundlePath: signature.directory, trust: signature.trust, now: NOW })).rejects.toThrow();
  });

  it.each(["not-a-sha256-digest", "A".repeat(64)])(
    "rejects invalid direct-profile policyHash %s",
    async (policyHash) => {
      const artifact = await makeArtifacts({ attestationPolicyHash: policyHash });
      await expect(verifyProvingGroundAttestation(artifact.jwt, {
        trust: artifact.trust,
        jwks: artifact.jwks,
        request: { intent: INTENT, txCommit: artifact.txCommit },
        now: NOW,
      })).rejects.toThrow("policyHash must be lowercase SHA-256 hex");
    }
  );

  it("rejects a mismatched audience", async () => {
    const artifact = await makeArtifacts({ audience: "wrong-audience" });
    await expect(verifyProofBundle({ bundlePath: artifact.directory, trust: artifact.trust, now: NOW })).rejects.toThrow("audience must include sigil-sign");
  });

  it("rejects trust substitution, unknown kids, and header/payload kid mismatch", async () => {
    const swapped = await makeArtifacts();
    const replacement = await generateKeyPair("EdDSA");
    const replacementJwk = await exportJWK(replacement.publicKey);
    await writeFile(join(swapped.directory, "jwks.json"), JSON.stringify({ keys: [{ ...replacementJwk, kid: "synthetic-signer", alg: "EdDSA", use: "sig" }] }));
    await expect(verifyProofBundle({ bundlePath: swapped.directory, trust: swapped.trust, now: NOW })).rejects.toThrow("does not match the trust manifest");
    const unknown = await makeArtifacts();
    unknown.trust.attestationKeys[0].kid = "unknown";
    await expect(verifyProofBundle({ bundlePath: unknown.directory, trust: unknown.trust, now: NOW })).rejects.toThrow("does not match the trust manifest");
    const duplicate = await makeArtifacts();
    const duplicateJwks = JSON.parse(await readFile(join(duplicate.directory, "jwks.json"), "utf8"));
    duplicateJwks.keys.push({ ...duplicateJwks.keys[0], x: "A".repeat(43) });
    await writeFile(join(duplicate.directory, "jwks.json"), JSON.stringify(duplicateJwks));
    await expect(verifyProofBundle({ bundlePath: duplicate.directory, trust: duplicate.trust, now: NOW })).rejects.toThrow("duplicate kid");
    const mismatch = await makeArtifacts({ payloadKid: "different-kid" });
    await expect(verifyProofBundle({ bundlePath: mismatch.directory, trust: mismatch.trust, now: NOW })).rejects.toThrow("header and payload kid do not match");
  });

  it("rejects a substituted operator key and supplied-canonical-only bundle", async () => {
    const otherOperator = await generateKeyPair("EdDSA");
    const otherOperatorJwk = await exportJWK(otherOperator.publicKey);
    const substituted = await makeArtifacts();
    await writeFile(join(substituted.directory, "operator-public-key.json"), JSON.stringify(otherOperatorJwk));
    await expect(verifyProofBundle({ bundlePath: substituted.directory, trust: substituted.trust, now: NOW })).rejects.toThrow("operator key does not match");
    const canonicalOnly = await makeArtifacts({ canonical: {
      schema: CANONICAL_POLICY_ENVELOPE_SCHEMA,
      canonicalizer: CANONICALIZER_VERSION,
      policy: { version: "2.1.0", tool_calls: { allowed: ["email.send"] } },
    } });
    await expect(verifyProofBundle({ bundlePath: canonicalOnly.directory, trust: canonicalOnly.trust, now: NOW })).rejects.toThrow("not derived from warranty.md");
  });

  it("binds the response, canonicalizer, PQC snapshot, and trust lifecycle", async () => {
    expect(CANONICALIZER_VERSION).toBe("@sigilcore/warrant-core@0.2.3");
    const responseMismatch = await makeArtifacts({ responseAttestation: "not-the-attestation" });
    await expect(verifyProofBundle({ bundlePath: responseMismatch.directory, trust: responseMismatch.trust, now: NOW })).rejects.toThrow("response.json intent_attestation");

    const historicalCanonicalizer = await makeArtifacts({ canonical: {
      schema: CANONICAL_POLICY_ENVELOPE_SCHEMA,
      canonicalizer: HISTORICAL_CANONICALIZER_VERSION,
      policy: JSON.parse(canonicalizePolicyObjectFrom021(parsePolicyMarkdownFrom021(WARRANTY))),
    } });
    await expect(verifyProofBundle({ bundlePath: historicalCanonicalizer.directory, trust: historicalCanonicalizer.trust, now: NOW })).resolves.toMatchObject({
      operatorSignatureValid: true,
    });

    const canonicalizerMismatch = await makeArtifacts();
    const canonical = JSON.parse(await readFile(join(canonicalizerMismatch.directory, "policy.canonical.json"), "utf8"));
    canonical.canonicalizer = "@sigilcore/warrant-core@0.2.0";
    await writeFile(join(canonicalizerMismatch.directory, "policy.canonical.json"), JSON.stringify(canonical));
    await expect(verifyProofBundle({ bundlePath: canonicalizerMismatch.directory, trust: canonicalizerMismatch.trust, now: NOW })).rejects.toThrow("unsupported canonicalizer envelope");

    const pqcSubstitution = await makeArtifacts({ pqcKeys: { keys: [{ ...PQC_KEY, publicKey: "BQYHCA" }] } });
    await expect(verifyProofBundle({ bundlePath: pqcSubstitution.directory, trust: pqcSubstitution.trust, now: NOW })).rejects.toThrow("PQC key does not match");

    const expiredTrust = await makeArtifacts();
    expiredTrust.trust.notAfter = "2029-12-31T23:59:59Z";
    await expect(verifyProofBundle({ bundlePath: expiredTrust.directory, trust: expiredTrust.trust, now: NOW })).rejects.toThrow("outside its validity window");

    const revokedTrust = await makeArtifacts();
    revokedTrust.trust.revokedAt = "2029-12-01T00:00:00Z";
    await expect(verifyProofBundle({ bundlePath: revokedTrust.directory, trust: revokedTrust.trust, now: NOW })).rejects.toThrow("has been revoked");
  });
});
