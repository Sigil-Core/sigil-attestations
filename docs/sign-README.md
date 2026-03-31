# sigil-sign | Deterministic Execution Firewall

*The core API that enforces pre‑execution authorization for autonomous agents via cryptographic Intent Attestations.*

[![Status](https://img.shields.io/badge/status-active--development-black)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red)](#)
[![Security](https://img.shields.io/badge/security-Intent--Attestation-green)](#)
[![Spec Version](https://img.shields.io/badge/spec-v0.x-blue)](#)

---

## Executive Summary

**sigil-sign** is the deterministic execution firewall for autonomous AI agents.

Language models are probabilistic. Execution must not be.

sigil-sign ensures that no high‑stakes action — onchain transaction, contract call, or treasury movement — executes without first passing deterministic policy evaluation and receiving a short‑lived, cryptographically signed **Intent Attestation** defined by the `sigil-attestations` specification.

Authorization is enforced *before execution*, not after loss.

---

## Architectural Principle

> Safety is not a property of prompts.  
> Safety is a property of infrastructure.

The sigil-sign API separates the:

- **Brain** → the AI reasoning layer  
- **Hands** → keys, RPC endpoints, and execution environments  

Execution proceeds only if the proposed action carries a valid, time‑bound Intent Attestation issued by sigil-sign.

---

## How It Works

1. **Intent Proposal**  
   The agent constructs a fully‑formed transaction (EOA) or UserOperation (ERC‑4337) and computes its binding hash (`txCommit` or `userOpHash`).

2. **Authorization Request**  
   The agent sends a `POST /v1/authorize` request to the sigil-sign API.

3. **Deterministic Policy Evaluation**  
   The request is validated (Zod schema enforcement), evaluated against `warranty.md`, and checked against allowlisted chainIds and policy constraints.

4. **Intent Attestation (Approval)**  
   If compliant, sigil-sign returns a short‑lived Ed25519‑signed JWT Intent Attestation conforming to the `sigil-attestations` specification and bound to:
   - `chainId`
   - `txCommit` or `userOpHash`
   - strict expiration (≤ 60 seconds)
   - issuer `sigil-core`
   - audience `sigil-sign`

5. **Deterministic Rejection**  
   If non‑compliant, sigil-sign returns a strictly typed JSON Rebound with a deterministic error code.

No execution should occur without a valid attestation.

---

## API Specification

### POST `/v1/authorize`

### Request Schema

```json
{
  "agentId": "string",
  "framework": "agentkit | eliza",
  "chainId": 1,
  "txCommit": "0x...",
  "intent": {
    "action": "wallet.transfer",
    "targetAddress": "0x...",
    "amount": "1000000000000000000",
    "calldata": "0x..."
  },
  "context": "string"
}
```

---

### Response Schema (Approved)

```json
{
  "status": "APPROVED",
  "intent_attestation": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "message": "Intent verified against warranty.md. Append attestation to transaction calldata."
}
```

---

### Response Schema (Denied)

```json
{
  "status": "DENIED",
  "error_code": "SIGIL_POLICY_VIOLATION_04",
  "message": "Transaction exceeds defined treasury limit.",
  "intent_attestation": null
}
```

---


### Minimal cURL Example

```bash
curl -X POST https://sign.sigilcore.com/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "agent-123",
    "framework": "agentkit",
    "chainId": 1,
    "txCommit": "0xabc123...",
    "intent": {
      "action": "wallet.transfer",
      "targetAddress": "0xdeadbeef...",
      "amount": "1000000000000000000",
      "calldata": "0x"
    },
    "context": "Treasury rebalance per warranty.md"
  }'
```

---

## Security Model

sigil-sign operates under a **deny‑by‑default execution model**.

Core guarantees:

- No private keys reside in AI model context.
- No raw API credentials are exposed to reasoning layers.
- All high‑stakes actions require deterministic pre‑execution authorization.
- Authorization decisions are cryptographically signed (Ed25519) and conform to the `sigil-attestations` specification.
- Attestations are short‑lived and binding‑specific.
- Unsupported chainIds are rejected by default.

sigil-sign assumes models may hallucinate or be prompt‑injected. Therefore, enforcement is externalized into deterministic infrastructure.

---

## Threat Model Summary

| Threat Vector | Risk | Mitigation in sigil-sign |
|--------------|------|--------------------------|
| Prompt Injection | Agent executes unintended action | Deterministic pre‑execution policy evaluation |
| Hallucinated Parameters | Malformed or malicious transaction | Strict Zod schema validation + commit binding |
| Privilege Escalation | Agent exceeds treasury or scope limits | warranty.md policy constraints |
| Replay Attacks | Reuse of old authorization | ≤ 60 second expiration + commit binding |
| Chain Mismatch | Execution on unsupported network | Explicit chainId allowlist |
| Credential Leakage | Keys exposed to reasoning layer | No keys ever enter model context |

---

## Security Standards

- **EdDSA (Ed25519) Signatures Only**  
  HS256 and symmetric signing are strictly prohibited.

- **Strict Schema Validation**  
  All inputs validated via Zod before policy evaluation.

- **Payload Limits**  
  100kb JSON body limit enforced.

- **Rate Limiting**  
  Deterministic per‑IP throttling on `/v1/authorize`.

- **Short Expiry Window**  
  Intent Attestations expire within 60 seconds.

---

## Specification Reference

Intent Attestations issued by sigil-sign conform to the public `sigil-attestations` specification.

Verification rules, claim structure, versioning policy, and JWK publication guidance are defined in that repository.

sigil-sign implements the issuing authority for that specification.

---

## Public Key Publication

Intent Attestation signatures are verifiable via Sigil’s published JWK set.

Public keys are exposed at:

`https://sign.sigilcore.com/.well-known/jwks.json`

Verification clients must:

1. Extract the `kid` from the JWT header.
2. Fetch or cache the JWK set.
3. Verify the Ed25519 signature.
4. Validate required claims per the `sigil-attestations` specification.

Private signing keys are never exposed.

---

## Deployment Topology

```
                ┌─────────────────────┐
                │   Cloudflare WAF    │
                │   + Rate Limiting   │
                └──────────┬──────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Global Load Balancer   │
              └──────────┬──────────────┘
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
┌───────────────────┐           ┌───────────────────┐
│ sigil-sign-nyc2   │           │ sigil-sign-ams3   │
│ Primary Region    │           │ Failover Region   │
└───────────────────┘           └───────────────────┘
         │                               │
         └───────────────┬───────────────┘
                         ▼
               ┌─────────────────────┐
               │  Policy + Assure    │
               │  + Attestation      │
               └─────────────────────┘
```

- Active/Passive regional deployment (NYC2 primary, AMS3 failover)
- Cloudflare origin certificates (HTTPS only)
- No direct public SSH access without key authentication
- Stateless API layer; no runtime state coupling

---

## Supported Chains (Day‑1 Allowlist)

| Chain | chainId | Status |
|-------|---------|--------|
| Ethereum Mainnet | 1 | Supported |
| Base | 8453 | Supported |
| Arbitrum One | 42161 | Supported |
| Optimism | 10 | Supported |
| Polygon | 137 | Supported |
| BNB Smart Chain | 56 | Supported |
| HyperEVM | 999 | Supported |

Any chainId not explicitly listed is rejected by default.

---

## Supported Frameworks (Day‑1)

| Framework | Status | Notes |
|------------|--------|-------|
| Coinbase AgentKit | Supported | Native EVM transaction flow |
| ELIZA OS | Supported | ERC‑4337 UserOperation flow |

Additional frameworks may integrate as long as they:

- Produce fully‑formed transactions or UserOperations
- Compute deterministic commit bindings
- Append valid Intent Attestations prior to execution

---

## Performance Targets (Initial SLA)

sigil-sign is designed for low‑latency pre‑execution authorization.

Target objectives (initial phase):

- **p50 latency:** < 75ms
- **p95 latency:** < 150ms
- **Availability target:** 99.9%

Latency targets apply to policy evaluation and Intent Attestation issuance only.

---

## Deterministic Error Code Classes

All error responses follow a strictly typed classification model.

| Class | Prefix | Description |
|-------|--------|------------|
| Validation Errors | SIGIL_VALIDATION_* | Schema violations, malformed fields, missing claims |
| Policy Violations | SIGIL_POLICY_* | Deterministic breach of warranty.md constraints |
| Authorization Failures | SIGIL_AUTH_* | Invalid, expired, or mismatched Intent Attestation |
| Internal Errors | SIGIL_INTERNAL_* | Unexpected infrastructure or runtime failure |

Error codes are stable and versioned under the `sigil-attestations` specification.

---

## Enterprise Mode (Roadmap)

For enterprise deployments, sigil-sign will support hardened execution environments including:

- AWS Nitro Enclaves (Trusted Execution Environments)
- HSM-backed Ed25519 key storage
- Dedicated VPC isolation
- Private connectivity (no public internet exposure)

These enhancements strengthen execution residency guarantees while preserving the non‑custodial doctrine.

---

## Production Readiness Checklist

Before production deployment, ensure:

- [ ] Ed25519 private key securely stored (KMS or HSM-backed in enterprise mode)
- [ ] Public JWK published at `/.well-known/jwks.json`
- [ ] Cloudflare WAF + rate limiting enabled
- [ ] TLS enforced (no HTTP fallback)
- [ ] Supported chain allowlist configured
- [ ] Deterministic error codes verified
- [ ] Logging structured and retention-limited
- [ ] No secrets stored in repository
- [ ] Health check endpoint (`/healthz`) operational

---

## Related Repositories

- **sigil-attestations** — Canonical Intent Attestation specification (Ed25519 JWT standard)
- **sigil-vault** — Non‑custodial JIT capability broker for execution control
- **ove** — Open Venture Engine (agent execution framework)
- **faf** — Fiduciary Agent Framework (legal‑technical wrapper)

---

## License

This repository is **proprietary and not open source**.

All rights reserved © Sigil Core.

No portion of this codebase may be copied, modified, distributed, or deployed without explicit written permission from Sigil Core.

Access to this repository does not grant any license to use the software in production or commercial environments unless separately authorized.

---

## Documentation

Full integration guides and policy engine documentation are coming soon.

→ **https://docs.sigilcore.com**
