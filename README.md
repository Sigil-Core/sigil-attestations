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

The attestation proves that a transaction intent passed deterministic policy evaluation at issuance time.

---

## Verification Rules (Normative)

Verification helpers in this repo strictly enforce:

- `alg` must equal **EdDSA** (Ed25519 only)
- `iss` must equal exactly **"sigil-core"**
- `exp` must be present and valid
- Payload must contain a valid `intent` object
- Signature must verify against a published JWK

Algorithms such as HS256, RS256, ES256 are explicitly rejected.

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

Current Status: `v0.x` (Hackathon Phase)

A `v1.0.0` release will indicate stable claim schema and validation rules.

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
