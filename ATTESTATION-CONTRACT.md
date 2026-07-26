# Proving Ground Attestation Contract v1

This document defines the `pg-commit-v1` verifier profile for signed Sigil Sign approvals. It supplements the existing strict `verifyIntentAttestation` API. It does not replace it. The package root remains browser and Workers safe; Node-only unpacked-bundle verification is available from `sigil-attestations/node` and through the `sigil-verify` CLI.

## Signed claim set

The current Sigil Sign signer emits an EdDSA JWT with these load-bearing claims:

| Claim | Requirement |
| --- | --- |
| `iss` | Equals the trusted manifest issuer, currently `sigil-core`. |
| `aud` | Contains `sigil-sign`. |
| `iat`, `exp` | Integer UNIX seconds. The authorization lifetime is one to 60 seconds. |
| `kid` | Present in both protected header and payload, with identical values. |
| `intentHash` | Lowercase SHA-256 hex of the request `txCommit`. |
| `policyHash` | Lowercase SHA-256 hex of the parsed Warrant policy object. |
| `chainId` | Optional positive safe integer. When present, it must exactly match the optional top-level request `chainId`. |
| `agentId`, `framework`, `provenance` | Signer metadata. These do not replace request binding. |

The profile intentionally does not require `payload.intent`, `targetAddress`, or any EVM-only field. Tool-call approvals bind through the commitment below.

## Request binding: `pg-commit-v1`

The proxy computes `txCommit` as lowercase SHA-256 hex over the UTF-8 bytes of `canonicalizePgCommitV1(intent)` from `@sigilcore/warrant-core@0.1.1`.

- Object keys sort by ECMAScript UTF-16 code-unit order.
- Array order remains unchanged.
- Only JSON values are permitted. Cycles, `undefined`, functions, symbols, bigint values, sparse arrays, accessors, and non-finite numbers reject.

The verifier recomputes this commitment from `request.json.intent`, requires it to equal `request.json.txCommit`, then requires `SHA-256(txCommit)` to equal the signed `intentHash`.

`request.json.chainId` is an optional top-level execution-network binding. It is not part of `pg-commit-v1`, which continues to hash only `request.json.intent`. The JWT claim and request field must either both be absent or both be positive safe integers with exactly the same value. This preserves chain-free tool-call approvals while rejecting a request moved to a different chain.

## Verification modes

Execution mode preserves the existing authorization boundary. A token that has expired fails.

Audit mode verifies the same EdDSA signature, issuer, audience, temporal structure, `kid` consistency, commitment, and policy binding. An expired token returns a successful historical-proof result with `authorizationExpired: true`. Audit mode never represents an expired authorization as executable.

## Trust manifest: `sigil-trust/v1`

Trust travels separately from a proof bundle. The accepted JSON shape is:

```json
{
  "schema": "sigil-trust/v1",
  "issuer": "sigil-core",
  "audience": "sigil-sign",
  "verifiedAlgorithms": ["EdDSA"],
  "informationalAlgorithms": ["ML-DSA-65"],
  "notBefore": "2026-01-01T00:00:00Z",
  "notAfter": "2026-04-01T00:00:00Z",
  "reviewAfter": "2026-02-01T00:00:00Z",
  "revokedAt": null,
  "attestationKeys": [{ "kid": "example", "jwkThumbprint": "RFC7638-base64url-thumbprint" }],
  "operatorKey": { "fingerprint": "sha256-hex-of-raw-ed25519-key" },
  "pqcKey": { "kid": "example-pqc", "fingerprint": "sha256-hex-of-raw-ml-dsa-public-key" }
}
```

`jwkThumbprint` is RFC 7638 SHA-256 base64url over the minimal Ed25519 JWK members `{ "crv", "kty", "x" }`. The operator fingerprint is lowercase SHA-256 hex over the decoded 32-byte Ed25519 public key. The manifest must be within its validity window, include EdDSA, and remain unrevoked.

The verifier selects the JWT key by the protected-header `kid`, requires a matching payload `kid`, and rejects a JWKS key that does not match the separately supplied manifest. It also rejects an operator public key that does not match the manifest. A bundle cannot establish its own trust root.

## Proof bundle layout

`sigil-verify` accepts an unpacked directory containing these required files:

```text
warranty.md
operator-public-key.json
attestation.jwt
request.json
response.json
jwks.json
policy.canonical.json
pqc-keys.json
VERIFY.md
```

`response.json.intent_attestation` must byte-match `attestation.jwt`. `warranty.md` must carry a final `## signature` block. The verifier checks that signature over the unsigned Warrant bytes, parses the Warrant with `@sigilcore/warrant-core@0.1.1`, and derives its hash independently.

`policy.canonical.json` uses this versioned envelope. Metadata never enters the policy hash:

```json
{
  "schema": "sigil-policy-canonical/v1",
  "canonicalizer": "@sigilcore/warrant-core@0.1.1",
  "policy": { "version": "2.1.0" }
}
```

The verifier requires the pinned `canonicalizer` identifier, canonical equality between `policy` and the parsed Warrant, equality between the two independently derived policy hashes, and equality with the signed `policyHash`.

`pqc-keys.json` and `VERIFY.md` remain required release-bundle materials but are informational in this EdDSA-only verifier milestone. The verifier does not verify ML-DSA-65 signatures, but it requires the declared `pqcKey.kid` and raw-key SHA-256 fingerprint in the separately supplied trust manifest to match the bundle snapshot. ML-DSA-65 signature verification is deferred.

## CLI

```sh
sigil-verify --bundle ./proof-bundle --trust ./sigil-trust.v1.json --mode audit --json
```

`--trust` is required during Phase 2 because the release does not include a real-environment manifest or fixture. It must come from a separately acquired trust source.

## Warrant authoring-surface impact

### Warrant Builder: no user-interface or signing change in Phase 2

The verifier consumes a downloaded signed Warrant through the exact `@sigilcore/warrant-core@0.1.1` parser and canonicalizer. It adds no Builder field, import rule, signing path, preview behavior, download format, deployment behavior, migration, or round-trip change. The release gate is the already-required Phase 1 Builder regression evidence plus this verifier's derived-policy test. Any policy hash difference between Builder output and the shared core blocks fixture release.

### Manual Warrant: no grid, sample, or authoring-flow change in Phase 2

The verifier treats a Manual Warrant artifact as an offline input and checks the final signature block, parsed canonical object, and derived hash. It does not add, remove, retitle, or reorder Manual Warrant samples, or alter import, preview, download, deployment, migration, or round-trip behavior. The release gate is the Phase 1 Manual Warrant regression evidence, the existing eleven-sample check, and Phase 6 verification of each materialized template against this CLI.
