import { describe, it, expect } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, importJWK } from "jose";
import { verifyIntentAttestation } from "../src/verify.js";
import {
  InvalidAlgorithmError,
  ExpiredAttestationError,
  InvalidIssuerError,
  InvalidPayloadError,
} from "../src/errors.js";

const VALID_INTENT = {
  action: "transfer",
  targetAddress: "0xABC123",
  amount: "1.5",
};

const REQUIRED_EXECUTION_GRANT_FIELDS = [
  "policy_hash",
  "manifest_sha256",
  "shim_id",
  "executor_id",
  "adapter",
  "adapter_version",
  "nonce",
  "issued_at",
  "expires_at",
] as const;

const makeExecutionGrant = (overrides: Record<string, unknown> = {}) => {
  const now = Math.floor(Date.now() / 1000);
  return {
    policy_hash: "policy-hash",
    manifest_sha256: "sha256:manifest",
    shim_id: "shim-1",
    executor_id: "executor-1",
    adapter: "structured-tool",
    adapter_version: "2.1.0",
    nonce: "nonce-test",
    issued_at: now,
    expires_at: now + 30,
    ...overrides,
  };
};

const MALFORMED_EXECUTION_GRANTS: Array<[string, unknown]> = [
  ["non-object payload", "not-an-object"],
  ...REQUIRED_EXECUTION_GRANT_FIELDS.flatMap(
    (field): Array<[string, unknown]> => [
      [`missing ${field}`, makeExecutionGrant({ [field]: undefined })],
      [`empty ${field}`, makeExecutionGrant({ [field]: "" })],
    ]
  ),
  ["non-integer issued_at", makeExecutionGrant({ issued_at: 1.5 })],
  ["non-integer expires_at", makeExecutionGrant({ expires_at: 1.5 })],
  [
    "non-positive window",
    makeExecutionGrant({ issued_at: 100, expires_at: 100 }),
  ],
  [
    "window longer than 300 seconds",
    makeExecutionGrant({ issued_at: 100, expires_at: 401 }),
  ],
  ["invalid repository_id", makeExecutionGrant({ repository_id: 42 })],
  ["empty repository_id", makeExecutionGrant({ repository_id: "" })],
];

async function makeEdDSAKeypairAndJWKS() {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.use = "sig";
  const jwks = { keys: [publicJwk] };
  return { privateKey, jwks };
}

describe("verifyIntentAttestation", () => {
  it("verifies a valid EdDSA token", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();

    const jwt = await new SignJWT({ intent: VALID_INTENT, policyHash: "policy-hash" })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    const result = await verifyIntentAttestation(jwt, jwks);

    expect(result.intent.action).toBe("transfer");
    expect(result.intent.targetAddress).toBe("0xABC123");
    expect(result.intent.amount).toBe("1.5");
    expect(result.claims.iss).toBe("sigil-core");
    expect(result.protectedHeader.alg).toBe("EdDSA");
  });

  it("accepts a token from a configured trusted issuer", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();

    const jwt = await new SignJWT({ intent: VALID_INTENT, policyHash: "policy-hash" })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("consortium-issuer")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    const result = await verifyIntentAttestation(jwt, jwks, {
      trustedIssuers: ["sigil-core", "consortium-issuer"],
    });

    expect(result.claims.iss).toBe("consortium-issuer");
  });

  it("preserves and validates Policy 2.1 execution capability claims", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const executionGrant = {
      policy_hash: "policy-hash",
      manifest_sha256: "sha256:manifest",
      shim_id: "shim-1",
      executor_id: "executor-1",
      adapter: "structured-tool",
      adapter_version: "2.1.0",
      nonce: "nonce-1",
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 30,
    };
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite", "git.push_fast_forward"],
      execution_grant: executionGrant,
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    const result = await verifyIntentAttestation(jwt, jwks);
    expect(result.claims.policyHash).toBe("policy-hash");
    expect(result.claims.capabilities).toEqual(["filesystem.overwrite", "git.push_fast_forward"]);
    expect(result.claims.execution_grant).toEqual(executionGrant);
  });

  it.each(["rpc:write", "bundler:send"])(
    "accepts the documented %s receipt scope",
    async (scope) => {
      const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
      const jwt = await new SignJWT({
        intent: VALID_INTENT,
        policyHash: "policy-hash",
        scope,
      })
        .setProtectedHeader({ alg: "EdDSA" })
        .setIssuer("sigil-core")
        .setExpirationTime("1h")
        .setIssuedAt()
        .sign(privateKey);

      const result = await verifyIntentAttestation(jwt, jwks);
      expect(result.claims.scope).toBe(scope);
    }
  );

  it.each(["admin", "", 4])(
    "rejects the unsupported receipt scope %j",
    async (scope) => {
      const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
      const jwt = await new SignJWT({
        intent: VALID_INTENT,
        policyHash: "policy-hash",
        scope,
      })
        .setProtectedHeader({ alg: "EdDSA" })
        .setIssuer("sigil-core")
        .setExpirationTime("1h")
        .setIssuedAt()
        .sign(privateKey);

      await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
        "scope claim must be rpc:write or bundler:send"
      );
    }
  );

  it("rejects malformed capability claims", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite", 4],
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(InvalidPayloadError);
  });

  it("rejects an execution grant bound to a different policy hash", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite"],
      execution_grant: {
        policy_hash: "other-policy-hash",
        manifest_sha256: "sha256:manifest",
        shim_id: "shim-1",
        executor_id: "executor-1",
        adapter: "structured-tool",
        adapter_version: "2.1.0",
        nonce: "nonce-1",
        issued_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 30,
      },
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(InvalidPayloadError);
  });

  it("rejects an expired execution grant", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite"],
      execution_grant: {
        policy_hash: "policy-hash",
        manifest_sha256: "sha256:manifest",
        shim_id: "shim-1",
        executor_id: "executor-1",
        adapter: "structured-tool",
        adapter_version: "2.1.0",
        nonce: "nonce-expired",
        issued_at: now - 60,
        expires_at: now - 1,
      },
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "execution_grant is expired or not yet valid"
    );
  });

  it("rejects an execution grant issued in the future", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite"],
      execution_grant: {
        policy_hash: "policy-hash",
        manifest_sha256: "sha256:manifest",
        shim_id: "shim-1",
        executor_id: "executor-1",
        adapter: "structured-tool",
        adapter_version: "2.1.0",
        nonce: "nonce-future",
        issued_at: now + 60,
        expires_at: now + 90,
      },
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "execution_grant is expired or not yet valid"
    );
  });

  it("allows the documented five-second issuance clock tolerance", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
      capabilities: ["filesystem.overwrite"],
      execution_grant: {
        policy_hash: "policy-hash",
        manifest_sha256: "sha256:manifest",
        shim_id: "shim-1",
        executor_id: "executor-1",
        adapter: "structured-tool",
        adapter_version: "2.1.0",
        nonce: "nonce-clock-tolerance",
        issued_at: now + 5,
        expires_at: now + 35,
      },
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).resolves.toBeDefined();
  });

  it.each([
    ["missing policyHash", undefined],
    ["non-string policyHash", 7],
  ])("rejects %s", async (_label, policyHash) => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      ...(policyHash !== undefined && { policyHash }),
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "Payload missing or invalid policyHash"
    );
  });

  it("rejects a token without exp", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "Payload missing or invalid exp"
    );
  });

  it("rejects a token without iat", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "Payload missing or invalid iat"
    );
  });

  it("rejects a token issued beyond the five-second clock tolerance", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt(Math.floor(Date.now() / 1000) + 6)
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      "iat claim is beyond the five-second clock tolerance"
    );
  });

  it("allows the documented five-second JWT issuance clock tolerance", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({
      intent: VALID_INTENT,
      policyHash: "policy-hash",
    })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt(Math.floor(Date.now() / 1000) + 5)
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).resolves.toBeDefined();
  });

  it.each(MALFORMED_EXECUTION_GRANTS)(
    "rejects execution grants with %s",
    async (_label, executionGrant) => {
      const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
      const jwt = await new SignJWT({
        intent: VALID_INTENT,
        policyHash: "policy-hash",
        capabilities: ["filesystem.overwrite"],
        execution_grant: executionGrant,
      })
        .setProtectedHeader({ alg: "EdDSA" })
        .setIssuer("sigil-core")
        .setExpirationTime("1h")
        .setIssuedAt()
        .sign(privateKey);

      await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
        "execution_grant claim is malformed"
      );
    }
  );

  it.each([
    ["missing capabilities", undefined],
    ["empty capabilities", []],
  ])(
    "rejects an execution grant with %s",
    async (_label, capabilities) => {
      const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
      const jwt = await new SignJWT({
        intent: VALID_INTENT,
        policyHash: "policy-hash",
        ...(capabilities !== undefined && { capabilities }),
        execution_grant: makeExecutionGrant(),
      })
        .setProtectedHeader({ alg: "EdDSA" })
        .setIssuer("sigil-core")
        .setExpirationTime("1h")
        .setIssuedAt()
        .sign(privateKey);

      await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
        "execution_grant requires at least one capability"
      );
    }
  );

  it("rejects a token signed with HS256 (wrong algorithm)", async () => {
    const secret = new TextEncoder().encode("super-secret-key-that-is-long-enough");

    const jwt = await new SignJWT({ intent: VALID_INTENT })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .sign(secret);

    const { jwks } = await makeEdDSAKeypairAndJWKS();

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      InvalidAlgorithmError
    );
  });

  it("rejects an expired token", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();

    const jwt = await new SignJWT({ intent: VALID_INTENT })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("-1s")
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      ExpiredAttestationError
    );
  });

  it("rejects a token with the wrong issuer", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();

    const jwt = await new SignJWT({ intent: VALID_INTENT })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("not-sigil-core")
      .setExpirationTime("1h")
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(
      InvalidIssuerError
    );
  });

  it("rejects an empty trusted issuer set", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();

    const jwt = await new SignJWT({ intent: VALID_INTENT })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .sign(privateKey);

    await expect(
      verifyIntentAttestation(jwt, jwks, { trustedIssuers: [] })
    ).rejects.toThrow(InvalidIssuerError);
  });
});
