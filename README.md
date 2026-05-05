# sigil-attestations | Intent Attestation Specification

**Canonical specification and verification helpers for Sigil OS Intent Attestations.**

[![Status](https://img.shields.io/badge/status-active--development-black)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Security](https://img.shields.io/badge/security-Intent--Attestation-green)](#)
[![Spec Version](https://img.shields.io/badge/spec-v0.x-blue)](#)

---

## Executive Summary

`sigil-attestations` defines the formal cryptographic contract for Sigil OS **Intent Attestations**.

This repository contains:

- The canonical JWT claim specification
- Deterministic validation requirements
- Error class definitions
- TypeScript verification helpers (Ed25519 / EdDSA only)
- Unit tests validating signature and claim enforcement

This repository does **not** contain private keys, signing infrastructure, policy engines, or production execution code.

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
- Issuer (`iss = "sigil-core"`)
- Audience (`aud = "sigil-sign"` for `/v1/authorize` attestations, or the operator-configured audience for RPC/bundler scoped receipts)
- Policy hash (`policyHash`) — SHA-256 of the canonical JSON serialization of the evaluated warranty policy, providing deterministic cryptographic binding between the attestation and the exact policy version in effect at issuance time
- Scope claim (`scope`) — present on RPC/bundler receipts; values are `rpc:write` or `bundler:send`

The attestation proves that a transaction intent passed deterministic policy evaluation (Sigil Lex) at issuance time, and which policy version made that decision.

**Note on PENDING state:** When a Sigil Lex Class 3 consensus hold is triggered, no Intent Attestation is issued. The `/v1/authorize` endpoint returns a `202 PENDING` response with a `holdId` instead. Intent Attestation issuance is deferred until the hold is resolved through Sigil Command. Downstream verifiers (including sigil-vault) must treat an absent attestation for a PENDING hold as a structurally valid non-authorization, not an error.

---

## Verification Rules (Normative)

Verification helpers in this repo strictly enforce:

- `alg` must equal **EdDSA** (Ed25519 only)
- `iss` must equal exactly **"sigil-core"**
- `aud` must be validated against the expected audience for the context
- `exp` must be present and valid
- `iat` must be present and not in the future (beyond a 5-second clock tolerance)
- Payload must contain a valid `intent` object
- `policyHash` must be present and treated as opaque by verifiers; auditors may cross-reference against known warranty.md versions
- `scope` must be validated if the attestation is being used as an RPC/bundler receipt
- Signature must verify against a published JWK from `/.well-known/jwks.json`

Algorithms such as HS256, RS256, ES256 are explicitly rejected.

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
