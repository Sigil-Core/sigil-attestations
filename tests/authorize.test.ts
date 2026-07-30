import { createHash } from "node:crypto";
import { describe, expect, it, beforeEach, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { hashPgCommitV1, hashPolicy, parsePolicyMarkdown } from "@sigilcore/warrant-core";
import { createNodeCryptoAdapter } from "@sigilcore/warrant-core/crypto/node";
import {
  AuthorizeVerificationError,
  AuthorizeVerificationErrorCode,
  verifyAuthorizeProofBundleForAudit,
  verifyAuthorizeProofBundleForExecution,
} from "../src/index.js";
import type { AuthorizeReplayStore, SigilAuthorizeProofBundleV1, SigilAuthorizeTrustV1 } from "../src/types.js";

const NOW = new Date("2030-01-01T00:00:00Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const WARRANTY = "version: 2.1.0\n\n## tool_calls\nallowed: web_fetch\n";
const WARRANTY_SIGNATURE = "A".repeat(86);
const SIGNED_WARRANTY = `${WARRANTY.trimEnd()}\n\n## signature\nsigil-sig: ${WARRANTY_SIGNATURE}\n`;
const INTENT = { action: "web_fetch", url: "https://docs.sigilcore.com/cc-1", metadata: { template: "tool-call" } };

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

const expectCode = async (promise: Promise<unknown>, code: AuthorizeVerificationErrorCode): Promise<void> => {
  await expect(promise).rejects.toMatchObject({ code });
};

// skipcq: JS-R1005 - One fixture factory deliberately exposes every independent signed-claim substitution used by this security suite.
const makeFixture = async (overrides: {
  intent?: Record<string, unknown>;
  requestTxCommit?: string;
  signedIntentHash?: string;
  signedPolicyHash?: string;
  expiresAt?: number;
  issuedAt?: number;
  payloadKid?: string;
  audience?: string;
  issuer?: string;
  trustReference?: Partial<SigilAuthorizeProofBundleV1["trust_reference"]>;
  trustKey?: Partial<SigilAuthorizeTrustV1["keys"][number]>;
  warranty?: string;
  chainId?: number;
} = {}) => {
  const signer = await generateKeyPair("EdDSA");
  const jwk = await exportJWK(signer.publicKey);
  const kid = "cc1-test-signer";
  const intent = overrides.intent ?? INTENT;
  const txCommit = await hashPgCommitV1(createNodeCryptoAdapter(), intent as Parameters<typeof hashPgCommitV1>[1]);
  const warranty = overrides.warranty ?? SIGNED_WARRANTY;
  const policyHash = await hashPolicy(createNodeCryptoAdapter(), parsePolicyMarkdown(warranty));
  const claims: Record<string, unknown> = {
    iss: overrides.issuer ?? "sigil-core",
    aud: overrides.audience ?? "sigil-sign",
    kid: overrides.payloadKid ?? kid,
    agentId: "cc1-agent",
    framework: "agentkit",
    intentHash: overrides.signedIntentHash ?? createHash("sha256").update(txCommit, "ascii").digest("hex"),
    policyHash: overrides.signedPolicyHash ?? policyHash,
    iat: overrides.issuedAt ?? NOW_SECONDS - 10,
    exp: overrides.expiresAt ?? NOW_SECONDS + 50,
    ...(overrides.chainId === undefined ? {} : { chainId: overrides.chainId }),
  };
  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid })
    .sign(signer.privateKey);
  const trust: SigilAuthorizeTrustV1 = {
    schema: "sigil-authorize-trust/v1",
    manifest_sha256: "a".repeat(64),
    issuer: "sigil-core",
    audience: "sigil-sign",
    keys: [{
      kid,
      jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x as string, alg: "EdDSA" },
      not_before: NOW_SECONDS - 1_000,
      not_after: NOW_SECONDS + 1_000,
      ...overrides.trustKey,
    }],
  };
  const bundle: SigilAuthorizeProofBundleV1 = {
    bundle_version: "sigil-authorize-proof/v1",
    verification_profile: "sigil-sign-authorize-v1",
    token,
    request: {
      agentId: "cc1-agent",
      framework: "agentkit",
      txCommit: overrides.requestTxCommit ?? txCommit,
      intent: intent as SigilAuthorizeProofBundleV1["request"]["intent"],
      ...(overrides.chainId === undefined ? {} : { chainId: overrides.chainId }),
    },
    policy: { warranty_md: warranty },
    trust_reference: {
      manifest_sha256: "a".repeat(64),
      issuer: "sigil-core",
      audience: "sigil-sign",
      ...overrides.trustReference,
    },
  };
  return { bundle, raw: new TextEncoder().encode(JSON.stringify(bundle)), trust, token, txCommit, policyHash };
};

const memoryReplayStore = (): AuthorizeReplayStore & {
  consumed: Set<string>;
  retainUntil: number[];
  verificationTimes: number[];
  maxClockDrifts: number[];
} => {
  const consumed = new Set<string>();
  const retainUntil: number[] = [];
  const verificationTimes: number[] = [];
  const maxClockDrifts: number[] = [];
  return {
    consumed,
    retainUntil,
    verificationTimes,
    maxClockDrifts,
    consumeIfUnused(replayId, expiration, verificationTime, maxClockDrift) {
      retainUntil.push(expiration);
      verificationTimes.push(verificationTime);
      maxClockDrifts.push(maxClockDrift);
      if (consumed.has(replayId)) return Promise.resolve({ status: "replayed" as const });
      consumed.add(replayId);
      return Promise.resolve({ status: "consumed" as const });
    },
  };
};

describe("sigil-sign-authorize-v1", () => {
  it("verifies a real Sign-shaped tool-call token from raw bytes in audit mode", async () => {
    const fixture = await makeFixture();
    const result = await verifyAuthorizeProofBundleForAudit(fixture.raw, fixture.trust, { verificationTime: NOW });
    expect(result).toMatchObject({
      mode: "audit",
      profile: "sigil-sign-authorize-v1",
      issuer: "sigil-core",
      txCommit: fixture.txCommit,
      policyHash: fixture.policyHash,
      expiredAtVerification: false,
    });
    const execution = await verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, memoryReplayStore());
    expect(execution).toMatchObject({
      mode: "execution",
      profile: "sigil-sign-authorize-v1",
    });
  });

  it("binds the EVM chain claim exactly", async () => {
    const fixture = await makeFixture({
      intent: { action: "wallet.transfer", targetAddress: "0x000000000000000000000000000000000000dEaD", amount: "1" },
      chainId: 1,
    });
    await expect(verifyAuthorizeProofBundleForAudit(fixture.raw, fixture.trust, { verificationTime: NOW })).resolves.toMatchObject({ mode: "audit" });
    const withoutChain = { ...fixture.bundle, request: { ...fixture.bundle.request } };
    delete withoutChain.request.chainId;
    await expectCode(
      verifyAuthorizeProofBundleForAudit(new TextEncoder().encode(JSON.stringify(withoutChain)), fixture.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.CLAIM_MISMATCH
    );
  });

  it("permits exactly one of 100 concurrent execution consumers and retains through exp plus 300 seconds", async () => {
    const fixture = await makeFixture();
    const store = memoryReplayStore();
    const results = await Promise.allSettled(
      Array.from({ length: 100 }, () => verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, store))
    );
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(99);
    for (const result of results.filter((entry) => entry.status === "rejected")) {
      expect((result as PromiseRejectedResult).reason).toMatchObject({ code: AuthorizeVerificationErrorCode.REPLAY_DENIED });
    }
    expect(store.retainUntil).toEqual(Array.from({ length: 100 }, () => NOW_SECONDS + 350));
    expect(store.verificationTimes).toEqual(Array.from({ length: 100 }, () => NOW_SECONDS));
    expect(store.maxClockDrifts).toEqual(Array.from({ length: 100 }, () => 30));
  });

  it("rejects expiry in execution while permitting historical audit evidence without replay access", async () => {
    const fixture = await makeFixture({ expiresAt: NOW_SECONDS - 1, issuedAt: NOW_SECONDS - 50 });
    const store = memoryReplayStore();
    await expectCode(
      verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, store),
      AuthorizeVerificationErrorCode.EXPIRED
    );
    const audit = await verifyAuthorizeProofBundleForAudit(fixture.raw, fixture.trust, { verificationTime: NOW });
    expect(audit.expiredAtVerification).toBe(true);
    expect(store.consumed.size).toBe(0);
  });

  it("rejects raw-bundle ambiguity before cryptographic processing", async () => {
    const fixture = await makeFixture();
    const duplicate = new TextEncoder().encode('{"bundle_version":"sigil-authorize-proof/v1","bundle_version":"sigil-authorize-proof/v1"}');
    await expectCode(
      verifyAuthorizeProofBundleForAudit(duplicate, fixture.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.BUNDLE_SCHEMA
    );
    const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...fixture.raw]);
    await expectCode(
      verifyAuthorizeProofBundleForAudit(bom, fixture.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.BUNDLE_ENCODING
    );
    const tooLarge = new Uint8Array(1024 * 1024 + 1);
    await expectCode(
      verifyAuthorizeProofBundleForAudit(tooLarge, fixture.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.BUNDLE_TOO_LARGE
    );
  });

  it("requires the CC-1 strict signed Warrant frame before hashing policy", async () => {
    const unsigned = await makeFixture({ warranty: WARRANTY });
    await expectCode(
      verifyAuthorizeProofBundleForAudit(unsigned.raw, unsigned.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.POLICY_PARSE
    );
    const malformedSignature = await makeFixture({ warranty: SIGNED_WARRANTY.replace(WARRANTY_SIGNATURE, "short") });
    await expectCode(
      verifyAuthorizeProofBundleForAudit(malformedSignature.raw, malformedSignature.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.POLICY_PARSE
    );
    const crlf = await makeFixture({ warranty: SIGNED_WARRANTY.replaceAll("\n", "\r\n") });
    await expectCode(
      verifyAuthorizeProofBundleForAudit(crlf.raw, crlf.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.POLICY_PARSE
    );
  });

  it("fails every trust, signature, and binding substitution with a stable code", async () => {
    const fixture = await makeFixture();
    await expectCode(
      verifyAuthorizeProofBundleForAudit(fixture.raw, { ...fixture.trust, manifest_sha256: "b".repeat(64) }, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.TRUST_REFERENCE_MISMATCH
    );
    await expectCode(
      verifyAuthorizeProofBundleForAudit(fixture.raw, { ...fixture.trust, keys: [] }, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.BUNDLE_SCHEMA
    );
    await expectCode(
      verifyAuthorizeProofBundleForAudit(
        new TextEncoder().encode(JSON.stringify({ ...fixture.bundle, request: { ...fixture.bundle.request, txCommit: "b".repeat(64) } })),
        fixture.trust,
        { verificationTime: NOW }
      ),
      AuthorizeVerificationErrorCode.COMMIT_MISMATCH
    );
    await expectCode(
      verifyAuthorizeProofBundleForAudit(
        new TextEncoder().encode(JSON.stringify({ ...fixture.bundle, policy: { warranty_md: SIGNED_WARRANTY.replace("web_fetch", "email.send") } })),
        fixture.trust,
        { verificationTime: NOW }
      ),
      AuthorizeVerificationErrorCode.POLICY_HASH_MISMATCH
    );
    const [header, payload, signature] = fixture.token.split(".");
    const changedSignature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    await expectCode(
      verifyAuthorizeProofBundleForAudit(
        new TextEncoder().encode(JSON.stringify({ ...fixture.bundle, token: `${header}.${payload}.${changedSignature}` })),
        fixture.trust,
        { verificationTime: NOW }
      ),
      AuthorizeVerificationErrorCode.SIGNATURE
    );
  });

  it("enforces lifetime, revocation, audit time, and replay-store availability failures", async () => {
    const future = await makeFixture({ issuedAt: NOW_SECONDS + 6, expiresAt: NOW_SECONDS + 50 });
    await expectCode(
      verifyAuthorizeProofBundleForAudit(future.raw, future.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.IAT_FUTURE
    );
    const revoked = await makeFixture({ trustKey: { revoked_at: NOW_SECONDS - 1 } });
    await expectCode(
      verifyAuthorizeProofBundleForAudit(revoked.raw, revoked.trust, { verificationTime: NOW }),
      AuthorizeVerificationErrorCode.TRUST_REVOKED
    );
    const fixture = await makeFixture();
    await expectCode(
      verifyAuthorizeProofBundleForAudit(fixture.raw, fixture.trust, { verificationTime: new Date(NOW.getTime() + 1) }),
      AuthorizeVerificationErrorCode.AUDIT_TIME_INVALID
    );
    await expectCode(
      verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, {
        consumeIfUnused: () => Promise.reject(new Error("unavailable")),
      }),
      AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE
    );
    const preConsumptionClockFence = vi.fn(() => Promise.resolve({ status: "clock_drift" as const }));
    await expectCode(
      verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, { consumeIfUnused: preConsumptionClockFence }),
      AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE
    );
    expect(preConsumptionClockFence).toHaveBeenCalledWith(expect.any(String), NOW_SECONDS + 350, NOW_SECONDS, 30);
    await expectCode(
      verifyAuthorizeProofBundleForExecution(fixture.raw, fixture.trust, { consumeIfUnused: () => Promise.resolve(undefined as never) }),
      AuthorizeVerificationErrorCode.REPLAY_UNAVAILABLE
    );
  });

  it("publishes the complete stable public error vocabulary", () => {
    expect(Object.values(AuthorizeVerificationErrorCode)).toEqual([
      "ERR_BUNDLE_ENCODING", "ERR_BUNDLE_TOO_LARGE", "ERR_BUNDLE_SCHEMA", "ERR_PROFILE_UNKNOWN",
      "ERR_TRUST_REFERENCE_MISMATCH", "ERR_KID_UNKNOWN", "ERR_KID_MISMATCH", "ERR_ALG_UNSUPPORTED",
      "ERR_SIGNATURE", "ERR_ISSUER", "ERR_AUDIENCE", "ERR_CLAIM_MISMATCH", "ERR_LIFETIME", "ERR_EXPIRED",
      "ERR_IAT_FUTURE", "ERR_TRUST_WINDOW", "ERR_TRUST_REVOKED", "ERR_AUDIT_TIME_INVALID", "ERR_COMMIT_MISMATCH",
      "ERR_INTENT_HASH_MISMATCH", "ERR_POLICY_PARSE", "ERR_POLICY_HASH_MISMATCH", "ERR_POLICY_TOO_LARGE",
      "ERR_REPLAY_DENIED", "ERR_REPLAY_UNAVAILABLE",
    ]);
    expect(new AuthorizeVerificationError(AuthorizeVerificationErrorCode.SIGNATURE, "redacted").code).toBe("ERR_SIGNATURE");
  });
});
