# sigil-attestations | Intent Attestation Specification

**The cryptographic specification and shared validation libraries for Sigil OS Intent Attestations.**

---

## Executive Summary

`sigil-attestations` defines the canonical specification for **Intent Attestations** — the cryptographically signed artifacts issued by `sigil-sign` that authorize agent execution.

This repository contains:

- The formal JWT structure specification
- Claim definitions and validation rules
- Deterministic error code mappings
- Chain binding requirements
- Commit binding requirements
- Verification guidelines
- Lightweight validation helpers (where applicable)

This repository does **not** contain private keys, signing infrastructure, or production execution code.

---

## Purpose in the Sigil Ecosystem

Sigil OS consists of three core services:

- **sigil-sign** → Evaluates intent and issues signed Intent Attestations
- **sigil-vault** → Releases execution capability after attestation validation
- **sigil-attestations** → Defines the cryptographic contract that binds them

This repository ensures that:

- Intent Attestations are verifiable offline
- Third parties can independently validate authenticity
- Developers can implement compatible verifiers
- Auditors can reason about the attestation format without access to private infrastructure

---

## Intent Attestation Overview

An Intent Attestation is an **Ed25519 (EdDSA) signed JWT** that binds:

- Agent identity
- Framework origin
- Chain ID
- Transaction or UserOp commit hash
- Strict expiry window (≤ 60 seconds)
- Issuer and audience claims

The attestation proves that a transaction intent passed deterministic policy evaluation at a specific point in time.

---

## Design Principles

- **Deterministic** — No ambiguous claim fields
- **Short-Lived** — Tight expiration windows
- **Chain-Bound** — Explicit supported chain allowlist
- **Commit-Bound** — Receipt binds to a specific tx hash or UserOp hash
- **Offline Verifiable** — No network call required to validate signature
- **Non-Custodial** — No private key handling inside this repo

---

## What This Repo Contains

- `/spec` — Formal Intent Attestation specification (claims, schema, examples)
- `/error-codes` — Deterministic validation vs policy vs internal error mappings
- `/examples` — Sample signed and unsigned payloads
- `/verification` — Example verification snippets (TypeScript / Python)

---

## What This Repo Does NOT Contain

- Signing keys
- Production signing logic
- Policy engines
- Execution infrastructure

Those live in `sigil-sign` and `sigil-vault`.

---

## Verification Model

An Intent Attestation must be verifiable by:

1. Extracting the JWT header and payload
2. Validating signature using published JWK
3. Confirming `iss`, `aud`, `exp`, and `chainId`
4. Recomputing or verifying the commit binding
5. Confirming the chain is supported

If all checks pass, the intent was authorized under Sigil policy at issuance time.

---

## Versioning Policy

The Intent Attestation specification follows **Semantic Versioning (SemVer)**.

Version format:

`MAJOR.MINOR.PATCH`

- **MAJOR** — Breaking changes to claim structure, required fields, or validation rules.
- **MINOR** — Backward-compatible additions (new optional claims, new supported chain bindings, additional verification guidance).
- **PATCH** — Clarifications, documentation fixes, or non-normative updates.

During the hackathon phase, the spec is published as `v0.x`.

A `v1.0.0` release will indicate:

- Stable claim schema
- Stable error code mappings
- Stable chain binding rules
- Formal verification examples

Consumers should always validate the `spec_version` claim (when present) to ensure compatibility.

---

## JWK Publication & Signature Verification

Intent Attestations are signed using **Ed25519 (EdDSA)**.

To enable offline verification, Sigil publishes a public JSON Web Key (JWK).

Verification model:

- The public JWK is published via a well-known endpoint (e.g., `/.well-known/jwks.json`).
- The JWK contains only public key material.
- Private signing keys are never exposed.

Recommended verifier flow:

1. Fetch or cache the public JWK set.
2. Match the `kid` (Key ID) in the JWT header.
3. Verify the Ed25519 signature.
4. Validate required claims.

Key rotation policy:

- New keys are introduced with new `kid` values.
- Old keys remain published for a defined overlap window.
- Expired keys are removed after all valid attestations signed with them have expired.

This ensures cryptographic continuity without breaking verification clients.

---

## Status

Specification v0.x (Hackathon Release)

This repository will evolve as additional binding modes and capability types are introduced.

---

## License

MIT License

This repository contains only specifications and validation helpers. It does not expose proprietary execution infrastructure.

---
