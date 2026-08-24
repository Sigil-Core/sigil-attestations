# sigil-attestations | Intent Attestation Specification

**Canonical specification and verification helpers for Sigil OS Intent Attestations.**

[![Status](https://img.shields.io/badge/status-active--development-black)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Security](https://img.shields.io/badge/security-Intent--Attestation-green)](#)
[![Spec Version](https://img.shields.io/badge/spec-sigil--attestations--v1-blue)](#)

---

## Executive Summary

`sigil-attestations` defines the formal cryptographic contract for Sigil OS **Intent Attestations**.

This repository does not define Agent Plugins package attestations. Intent
Attestations bind a requested action to an authorization decision. Agent Plugin
package checks are distributed separately as the public
[`@sigilcore/plugin-attest`](https://www.npmjs.com/package/@sigilcore/plugin-attest)
package. Do not treat one attestation type as evidence for the other.

This repository contains:

- The canonical JWT claim specification
- Deterministic validation requirements
- Error class definitions
- TypeScript verification helpers (Ed25519 / EdDSA only)
- Unit tests validating signature and claim enforcement

For the Proving Ground profile, see [`ATTESTATION-CONTRACT.md`](./ATTESTATION-CONTRACT.md). The browser and Workers-safe package root exports attestation profile verification. The Node-only proof-bundle verifier is available from `sigil-attestations/node`; the packaged `sigil-verify` command uses that Node-only surface.

This repository does **not** contain private keys, signing infrastructure, policy engines, or production execution code.

## Development dependency contract

Use Node 22.22.0 and npm 11.12.1. Install npm with
`npm install --global npm@11.12.1`, then install the reviewed dependency tree
with `npm ci`; do not regenerate `package-lock.json` during normal development. The
direct Vitest, Vite, PostCSS, and esbuild dependencies keep the browser
root-import test explicit while pinning the audited development toolchain.

---

## CC-1 authorization proof verification

The package root exports `sigil-sign-authorize-v1` verification for raw proof-bundle bytes. The caller must acquire `sigil-authorize-trust/v1` separately. A proof bundle can reference that trust configuration, but cannot supply a trust root or a bearer key.

- `verifyAuthorizeProofBundleForExecution(rawBundle, trust, replayStore)` requires a currently valid 60-second authorization and an atomic, durable replay-store consumption. Its `mode: "execution"` nominal result is the only execution-authorization result. The result retains the authenticated `agentId`, `framework`, and optional `chainId` request scope. Before consuming, the store must reject expiry and more than 30 seconds of clock drift, and retain accepted replay identifiers through `exp + 300` seconds. The verifier rechecks expiry after consumption and returns no authority if the proof expires during the store operation.
- `verifyAuthorizeProofBundleForAudit(rawBundle, trust, { verificationTime })` verifies historical evidence without reading or writing replay state. It retains the same authenticated request scope, reports expiry at that time, and cannot grant execution authority.
- Both APIs require a strict CC-1 signed Warrant, derive the policy hash from its unsigned bytes through the pinned `@sigilcore/warrant-core` canonicalizer, and reject bundles larger than 1 MiB or Warrants larger than 256 KiB. A CC-1 proof bundle carries no canonicalizer field and is rejected if one is present; `CANONICALIZER_VERSION` identifies the canonicalizer in the separate `sigil-policy-canonical/v1` directory-bundle envelope described below.

The older `sigil-verify` directory-bundle interface remains available for historical Proving Ground evidence. This package verifies `sigil-policy-canonical/v1` bundles; it does not emit them. An emitter must stamp the current `@sigilcore/warrant-core@0.4.0` identifier. The verifier also accepts the prior `0.2.3` and `0.2.1` identifiers, only to verify already-issued bundles, and rejects every other value.

`CANONICALIZER_VERSION` identifies canonicalization behavior, not the installed npm version, so it does not track the `package.json` pin and is not expected to match it. It advances when a `@sigilcore/warrant-core` release changes canonicalization output for a policy both releases accept, or widens the set of policies that can be canonicalized at all. In either case the previous value moves into `HISTORICAL_CANONICALIZER_VERSIONS` so already-issued bundles stay verifiable. The pin may therefore sit ahead of the identifier.

Pin and identifier now agree at `0.4.0`. Measured against a 20-policy corpus drawn from the shipped `sigil-open-framework` examples, `sigil-sign` fixtures, and this package's own test Warrant, every policy accepted by both releases canonicalizes to byte-identical output and the same policy hash under `0.2.1`, `0.2.3`, `0.2.4`, `0.3.0`, and `0.4.0`. Thirteen policies fall in that shared domain and none of them differs. Advancing the identifier therefore changed no hash and invalidated no already-issued bundle, and `0.2.3` and `0.2.1` remain accepted for verification.

What `0.4.0` changed is the accepted policy-version range, which is why the identifier had to move. `0.2.3` supports Policy `0.x`, `1.x`, `2.0.x`, and `2.1.x`; `0.3.0` adds `2.2.x`; `0.4.0` adds `2.3.x`, along with a compiled response-policy surface and a `response.deny_string` custom rule that earlier releases have no emission path for. Two policies in the corpus, `developer-toolkit/warranty-policy.md` and `examples/mcp-server-agent/warranty.md`, are Policy `2.3.0` and are canonicalized by `0.4.0` after being rejected outright by every earlier release. A bundle built from such a policy and stamped `0.2.3` would have named a canonicalizer that could not have produced it.

The test for whether the identifier needs to move is behavioral, never a version-string comparison and never a tarball diff alone: canonicalize a corpus under both releases, compare output bytes across the shared accepted domain, then compare the accepted domains themselves. A prior identifier is retained for verification only while its output is proven identical on the shared domain; retention is an allowlist of values a bundle may legitimately carry, so a release that was never an identifier stays rejected even when its output matches.

Warrant Builder and Manual Warrant receive no UI, authoring, signing, import, preview, download, deployment, migration, or round-trip change from this verifier. Builder and Manual artifacts remain inputs to verification. Release evidence must include the relevant authoring-surface regressions and the CC-1 derived-policy checks.

---

## Proving Ground verifier release

The CC-1 raw-proof verifier is available as the immutable npm prerelease `sigil-attestations@0.2.1-rc.2`. Install the exact version so prerelease updates cannot move the dependency implicitly:

```sh
npm install --save-exact sigil-attestations@0.2.1-rc.2
```

RC-2 is configured to publish through the repository's trusted GitHub Actions publisher without a repository npm token. The workflow is configured to publish the same tested tarball attached to the immutable GitHub Release and request npm registry provenance. After successful publication, `next` points to RC-2. The bootstrap RC-1 publication remains the `latest` tag until a stable release receives separate approval. RC-1 was the interactive first publication required before npm permitted a trusted publisher to be configured for the new package name. Its registry shasum matches its immutable GitHub Release tarball, but that first npm version does not carry an npm registry provenance statement.

### Historical Proving Ground release

The final Proving Ground verifier is the GitHub Release [`v0.2.0`](https://github.com/Sigil-Core/sigil-attestations/releases/tag/v0.2.0). It promotes the unchanged `v0.2.0-rc.2` candidate at commit [`568a327224477e7416688c3cfdb50bbac4950bfb`](https://github.com/Sigil-Core/sigil-attestations/commit/568a327224477e7416688c3cfdb50bbac4950bfb). This launch uses GitHub Release artifacts only. It does not publish the verifier to npm.

The final release retains the immutable candidate artifact name and bytes:

- `sigil-attestations-0.2.0-rc.2.tgz`, SHA-256 `e7d4d9364b1668e184104c0bbe567d21f6bd23ae55c53c0ba8ec00638a01ba25`
- `sigil-trust.v1.json`, SHA-256 `ff4a1f91cbc840d4909394d4943389d7303d13d943a0ee1350243c35f8c59bb5`

Download each artifact and its companion checksum from the final `v0.2.0` release, verify the checksum before use, then install the local tarball:

```sh
curl -LO https://github.com/Sigil-Core/sigil-attestations/releases/download/v0.2.0/sigil-attestations-0.2.0-rc.2.tgz
curl -LO https://github.com/Sigil-Core/sigil-attestations/releases/download/v0.2.0/sigil-attestations-0.2.0-rc.2.tgz.sha256
shasum -a 256 -c sigil-attestations-0.2.0-rc.2.tgz.sha256
npm install --global ./sigil-attestations-0.2.0-rc.2.tgz
```

Acquire `sigil-trust.v1.json` separately from the proof bundle. The final release provides the trust file and its checksum as distinct assets:

```sh
curl -LO https://github.com/Sigil-Core/sigil-attestations/releases/download/v0.2.0/sigil-trust.v1.json
curl -LO https://github.com/Sigil-Core/sigil-attestations/releases/download/v0.2.0/sigil-trust.v1.json.sha256
shasum -a 256 -c sigil-trust.v1.json.sha256
```

### Verify a live Proving Ground proof

At [sigilcore.com/proving-ground](https://sigilcore.com/proving-ground), run a signed-clearance scenario, wait for all four browser verification links to pass, then download the proof bundle. Signed-clearance scenarios use `/v1/authorize`; PENDING and DENIED test-run scenarios do not produce a signed proof bundle. Unpack the download, then supply the separately acquired trust manifest:

```sh
sigil-verify --bundle ./sigil-proving-ground-proof --trust ./sigil-trust.v1.json --mode execution --json
sigil-verify --bundle ./sigil-proving-ground-proof --trust ./sigil-trust.v1.json --mode audit --json
```

Execution mode verifies a currently valid authorization and rejects it after its 60-second lifetime. Audit mode verifies the same historical signature, policy, trust, and request binding after expiry, reporting `authorizationExpired: true`; it never restores execution authority.

The release verifies the Ed25519 envelope. `pqc-keys.json` remains an informational proof-bundle artifact, and this verifier does not verify ML-DSA-65 signatures.

---

## Role in the Sigil Architecture

Sigil OS consists of three primary components:

- **sigil-sign** → Evaluates intent and issues signed Intent Attestations
- **sigil-vault** → Releases execution capability after attestation validation
- **sigil-attestations** → Defines and verifies the attestation format

This repository ensures that:

- Intent Attestations are verifiable offline
- Third parties can independently validate authenticity
- Developers can implement compatible verifiers
- Auditors can reason about the attestation format without access to private infrastructure

---

## Repository Structure

```
sigil-attestations/
  src/
    index.ts          # Barrel exports
    verify.ts         # verifyIntentAttestation implementation
    errors.ts         # Strongly-typed verification errors
    types.ts          # Intent and payload type definitions
  tests/
    verify.test.ts    # Unit tests (Vitest)
  package.json
  tsconfig.json
  README.md
```

---

## Intent Attestation Overview

An Intent Attestation is an **Ed25519 (EdDSA) signed JWT** that binds:

- Agent identity
- Framework origin
- Chain ID
- Transaction commit (`txCommit`) or ERC-4337 `userOpHash`
- Strict expiration window (≤ 60 seconds)
- Issuer (`iss`) in the verifier's trusted issuer set. The default trusted issuer set contains only `"sigil-core"`.
- Audience (`aud = "sigil-sign"` for `/v1/authorize` attestations, or the operator-configured audience for RPC/bundler scoped receipts)
- Policy hash (`policyHash`) — SHA-256 of the canonical JSON serialization of the evaluated warranty policy, providing deterministic cryptographic binding between the attestation and the exact policy version in effect at issuance time
- Scope claim (`scope`) — present on RPC/bundler receipts; values are `rpc:write` or `bundler:send`
- Policy 2.1 execution capability claims (`capabilities` and optional `execution_grant`) when the signer binds an attestation to a trusted structured execution boundary
- Hybrid PQC signature (`pqc`, OPTIONAL) — a parallel ML-DSA-65 signature over the canonicalized claim set, present when the issuing signer declares the `pqc_hybrid_attestations` extended capability

The attestation proves that a transaction intent passed deterministic policy evaluation (Sigil Lex) at issuance time, and which policy version made that decision.

**Note on PENDING state:** When a Sigil Lex Class 3 consensus hold is triggered, no Intent Attestation is issued. The `/v1/authorize` endpoint returns a `202 PENDING` response with a `holdId` instead. `PENDING` is a non-authorization, and the current task must not retry or execute it. A signer that supports hold resolution may accept only an authenticated out-of-band decision and then reauthorize the exact held intent. Any resulting Intent Attestation is newly issued and separate from the pending result. Downstream verifiers, including sigil-vault, must treat an absent attestation for a PENDING hold as a structurally valid non-authorization, not an error.

---

## Verification Rules (Normative)

Verification helpers in this repo strictly enforce:

- `alg` must equal **EdDSA** (Ed25519 only)
- `iss` must be present in the verifier's trusted issuer set. If no set is configured, the helper trusts only **"sigil-core"**
- `aud` must be validated against the expected audience for the context
- `exp` must be present and valid
- `iat` must be present and not in the future (beyond a 5-second clock tolerance)
- Payload must contain a valid `intent` object
- `policyHash` must be present and treated as opaque by verifiers; auditors may cross-reference against known warranty.md versions
- `scope` must be validated if the attestation is being used as an RPC/bundler receipt
- `capabilities`, when present, must be a list of non-empty capability identifiers
- `execution_grant`, when present, must bind a policy hash, effect manifest hash, shim, executor, adapter, nonce, and bounded issuance window
- Signature must verify against a published JWK from `/.well-known/jwks.json`

Algorithms such as HS256, RS256, ES256 are explicitly rejected.

## Hybrid Post-Quantum Signature Claim (Extended)

A signer with the `pqc_hybrid_attestations` extended capability embeds an OPTIONAL `pqc` claim in every approved attestation, carrying a parallel ML-DSA-65 (FIPS 204) signature over the same claim set:

```json
"pqc": {
  "alg": "ML-DSA-65",
  "kid": "<pqc key identifier>",
  "ctx": "sigil-pqc-attestation-v1",
  "canonicalization": "json-sorted-v1",
  "sig": "<base64url ML-DSA-65 signature>"
}
```

The signature is computed over the UTF-8 bytes of the signing context `sigil-pqc-attestation-v1`, a newline, then the canonical JSON of the claim set with the `pqc` claim removed. Canonicalization `json-sorted-v1`: recursively sort object keys in ascending lexicographic order, preserve array order, serialize as compact JSON.

PQC-aware verifiers fetch ML-DSA-65 public keys from the issuer's `pqc_keys_uri` (hosted reference signer: `https://sign.sigilcore.com/v1/pqc-keys`; canonical application path `/.well-known/sigil-pqc-keys.json`). The Ed25519 JWT signature remains mandatory and is verified exactly as specified above; the `pqc` claim never replaces classical verification. Verifiers without PQC support MUST ignore the claim.

The verification helpers in this repository verify the Ed25519 envelope only; ML-DSA-65 verification requires a PQC-capable library.

## Trusted Issuer Configuration (Normative)

Verifiers MUST treat issuer trust as configuration, not as a code-level
monopoly lock. The default trusted issuer set is:

```json
["sigil-core"]
```

Federated deployments add approved issuers to the verifier configuration:

```ts
await verifyIntentAttestation(token, jwks, {
  trustedIssuers: ["sigil-core", "consortium-issuer"]
});
```

An implementation MUST reject an attestation whose `iss` claim is absent from
the configured trusted issuer set, even when the signature is otherwise valid.

---

## SOF Core Policy Minimum (Normative)

A signer that claims SOF Core Conformance MUST evaluate every received intent
against the operator's `warranty.md` policy before issuing an Intent
Attestation.

For EVM intents, a Core Conformant signer MUST support the following Class 1
structural rule fields from the FAF `warranty.md` schema:

- `max_transaction_eth` — hard ceiling on EVM transaction value
- `allowed_actions` — global action allowlist
- `allowed_chains` — permitted chain ID allowlist
- `chain_actions` — optional per-chain action overrides

When `chain_actions` defines rules for the submitted `chainId`, those
per-chain actions take precedence over `allowed_actions`. The signer MUST reject
any intent that violates a supported Class 1 rule and MUST NOT issue an Intent
Attestation for that intent.

Class 2 semantic rules, Class 3 consensus holds, capability-broker
integration, and operator oversight surfaces are Extended Conformance
capabilities unless a later specification version makes them mandatory.

---

## SOF Version Header (Normative)

The current SOF attestation specification identifier is
`sigil-attestations-v1`.

Every conforming authorization decision response MUST include the HTTP response
header:

```http
X-SOF-Version: sigil-attestations-v1
```

This header declares the SOF wire contract used for the response. It does not
replace JWT verification, claim validation, JWKS lookup, or policyHash audit
checks.

---

## Conformance Discovery (Normative)

Every conforming signer MUST publish an unauthenticated JSON conformance
declaration at:

```text
/.well-known/sof-conformance.json
```

The endpoint MUST be served over TLS in production and MUST return
`Content-Type: application/json`.

Required fields:

| Field | Type | Requirement |
|---|---|---|
| `spec_version` | string | MUST equal `sigil-attestations-v1` for this specification |
| `conformance_level` | string | MUST be `core` or `extended` |
| `extended_capabilities` | string[] | MUST be present; empty for Core-only signers |
| `implementation_name` | string | Human-readable implementation name |
| `implementer` | string | Organization or operator asserting conformance |
| `contact` | string | Contact URI or email for security/spec issues |
| `jwks_uri` | string | Absolute URL for the signer's JWKS endpoint |
| `evaluated_against` | string | Reference target or test suite used for interoperability checks |
| `self_asserted` | boolean | `true` until formal conformance testing has certified the implementation |
| `asserted_at` | string | ISO 8601 UTC timestamp for the declaration |

`extended_capabilities` values are:

- `class_2`
- `class_3`
- `capability_broker`
- `operator_oversight`
- `pqc_hybrid_attestations`

Signers declaring `pqc_hybrid_attestations` additionally publish a `pqc_keys_uri` field pointing at their ML-DSA-65 public key set and list `ML-DSA-65` alongside `EdDSA` in an `attestation_algorithms` array.

Example:

```json
{
  "spec_version": "sigil-attestations-v1",
  "conformance_level": "core",
  "extended_capabilities": [],
  "implementation_name": "Acme Signer",
  "implementer": "Acme Audit Firm",
  "contact": "security@acme.example",
  "jwks_uri": "https://signer.acme.example/.well-known/jwks.json",
  "evaluated_against": "sign.sigilcore.com",
  "self_asserted": true,
  "asserted_at": "2026-05-05T00:00:00Z"
}
```

---

## Public Key Publication

Intent Attestations are verified using Sigil’s public JWKS endpoint:

```
/.well-known/jwks.json
```

Verification flow:

1. Fetch or cache the JWKS
2. Match JWT `kid` to JWK
3. Verify Ed25519 signature
4. Validate claims
5. Validate commit binding

Private signing keys are never exposed.

---

## Error Model

Verification helpers expose strongly typed errors:

- `SigilVerificationError` (base)
- `InvalidAlgorithmError`
- `InvalidIssuerError`
- `ExpiredAttestationError`
- `InvalidPayloadError`
- `InvalidSignatureError`

This allows deterministic error handling across runtimes.

---

## Versioning Policy

The Intent Attestation specification follows **Semantic Versioning (SemVer)**.

- **MAJOR** — Breaking changes to required claims or validation rules
- **MINOR** — Backward-compatible additions
- **PATCH** — Documentation or non-normative fixes

Current specification identifier: `sigil-attestations-v1`

The npm package version may differ from the SOF specification identifier.
Package releases version the helper library; the specification identifier
versions the wire contract that signers and verifiers claim conformance to.

---

## What This Repo Does NOT Contain

- Private signing keys
- Production signing infrastructure
- Policy engine implementation
- Vault execution logic

Those live in `sigil-sign` and `sigil-vault`.

---

## License

MIT License

This repository contains only specifications and verification helpers.

---
