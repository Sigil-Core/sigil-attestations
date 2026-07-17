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

  it("rejects malformed capability claims", async () => {
    const { privateKey, jwks } = await makeEdDSAKeypairAndJWKS();
    const jwt = await new SignJWT({ intent: VALID_INTENT, capabilities: ["filesystem.overwrite", 4] })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("sigil-core")
      .setExpirationTime("1h")
      .setIssuedAt()
      .sign(privateKey);

    await expect(verifyIntentAttestation(jwt, jwks)).rejects.toThrow(InvalidPayloadError);
  });

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
