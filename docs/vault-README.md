# sigil-vault | Key Sequestration & Execution Residency

*The credential control plane for Sigil OS — isolates secrets from agent reasoning and releases capabilities only after deterministic authorization.*

[![Status](https://img.shields.io/badge/status-design--phase-black)](#)
[![License](https://img.shields.io/badge/license-Proprietary-red)](#)
[![Security](https://img.shields.io/badge/security-Key--Sequestration-green)](#)

---

## Executive Summary

**sigil-vault** is the non-custodial capability broker of Sigil OS.

Vault does **not** hold private keys, treasury funds, or long‑lived signing authority.

Instead, Vault operates as a **Just‑In‑Time (JIT) capability broker** that releases narrowly scoped, time‑bound execution privileges only after receiving a valid cryptographic **Intent Attestation** (as defined in the `sigil-attestations` specification) from sigil-sign.

If **sigil-sign** determines *whether* an action is authorized, **sigil-vault** determines *how* that authorized action is allowed to execute — without ever exposing secrets to the agent.

---

## Non-Custodial Doctrine

> **Sigil Vault never holds your money. It holds the cryptographic brakes that allow your money to move.**
>
> - No long-lived private keys are stored.
> - No treasury assets are custodied.
> - No standing credentials are granted to agents.
> - All capabilities are short-lived, scoped, and conditional.
>
> If Sigil held customer keys or funds, it would become a regulated custodian. Vault is intentionally architected to avoid that regulatory surface area by operating purely as a Just-In-Time capability broker.

---

## Why This Matters

Founders deploying autonomous agents inherit full fiduciary liability.

If an agent hallucinates, is prompt-injected, or executes an unintended action, the human operator bears responsibility.

Vault ensures:

- Agents never possess permanent execution authority.
- Execution privileges are structurally isolated from reasoning layers.
- Every high-risk action is cryptographically traceable.
- Auditors can verify that capability release followed deterministic authorization.

Vault converts “AI trust” into **system-enforced structural guarantees**.

---

## What Vault Does

Vault provides deterministic control over credential and execution capability release through a strictly non‑custodial architecture.

Core functions:

- **JIT Key Mediation** — Requests short‑lived, single‑use signatures or scoped credentials from client‑owned systems (e.g., Fireblocks, Utila, AWS KMS, HSM providers).
- **MPC Co‑Signature Authorization** — For EVM execution, Vault authorizes external MPC signers; it does not sign transactions itself.
- **API‑Key Brokering** — Injects temporary, scoped Web2 credentials (e.g., AWS, Stripe, Salesforce) into agent runtimes for a limited execution window.
- **Capability Isolation** — Ensures no standing privileges exist within agent reasoning layers.
- **Cryptographic Audit Linking** — Links Intent Attestation → Capability Release → Execution outcome.

Vault never stores or controls long‑lived private keys.

---

## Relationship to Sigil Sign

Vault is strictly downstream of sigil-sign.

- **sigil-sign** evaluates intent and issues a cryptographically signed Intent Attestation (Ed25519 JWT) conforming to the `sigil-attestations` specification.
- **sigil-vault** validates that attestation and, if valid, requests a short‑lived execution capability from the client’s key infrastructure.

Vault does not determine policy.
Vault does not determine authorization.
Vault enforces capability release only after authorization.

Day‑1 (March 4) ships with sigil-sign.
Vault capabilities follow in the next sprint.

---

## Security Model

sigil-vault operates under a **strictly non‑custodial, deny‑by‑default capability model**.

Security doctrine:

- Vault never holds long‑lived private keys.
- Vault never custodies treasury assets.
- Vault never grants standing credentials to agents.
- All capability release is time‑bound and scoped.
- Capability release is conditional on a valid Intent Attestation that conforms to the `sigil-attestations` specification.

Vault assumes:

- Language models are probabilistic.
- Agents may hallucinate or be prompt‑injected.
- External systems may attempt privilege escalation.

Therefore, Vault structurally isolates secrets from reasoning layers and releases execution power only under deterministic, cryptographically verifiable conditions.

---

## Day‑1 Capability Vectors (Post‑March 4)

Vault supports two distinct go‑to‑market vectors:

### 1. EVM Execution (Web3 Vector)

- Accept validated Intent Attestation from sigil-sign.
- Validate chain binding and commit binding.
- Forward attestation to external MPC provider (e.g., Utila, Fireblocks, Station70).
- Request single‑use co‑signature or short‑lived signing capability.
- Return execution result.

Vault authorizes the signer — it does not sign.

### 2. API‑Key Brokering (TradFi / Private Equity Vector)

- Accept validated Intent Attestation.
- Request short‑lived, scoped credential from AWS KMS / IAM / enterprise system.
- Inject credential into agent runtime for ≤ 60 seconds.
- Revoke or expire credential automatically.

This enables agents to safely touch:

- Stripe
- Salesforce
- Healthcare databases
- Cloud infrastructure
- Internal enterprise systems

Without ever granting standing privileges.

---

## Compliance & Enterprise Posture

Sigil Vault is architected for enterprise deployment.

Compliance positioning:

- Built to align with ISO 42001 (AI Security)
- ISO 27001
- SOC 2 Type 2 standards
- Formal observation window underway via Delve

Vault produces cryptographically linked audit chains:

Agent Prompt → ASSURANCE.md Policy → Intent Attestation → Capability Release → Execution

Future enterprise deployments will support:

- Trusted Execution Environments (AWS Nitro Enclaves)
- Hardware Security Modules (HSM)
- Isolated execution residency

---

## Deterministic Execution Flow

Vault enforces a strict four-step execution sequence:

1. **Intent Submission** — Agent sends intent to `sigil-sign`.
2. **Intent Attestation** — `sigil-sign` issues an Ed25519-signed Intent Attestation defined by the `sigil-attestations` specification.
3. **Capability Release** — `sigil-vault` validates the attestation and requests a short-lived execution credential from client-owned infrastructure.
4. **Execution & Expiry** — The action executes; capability automatically expires or is revoked.

No execution occurs without cryptographic authorization.

---

## Architecture Overview

```
            ┌──────────────────────┐
            │      AI Agent        │
            │  (ELIZA / AgentKit)  │
            └────────────┬─────────┘
                         │
                         │ Intent
                         ▼
            ┌──────────────────────┐
            │     sigil-sign       │
            │  Deterministic Sentry│
            └────────────┬─────────┘
                         │
                         │ Intent Attestation (Ed25519 JWT)
                         ▼
            ┌──────────────────────┐
            │     sigil-vault      │
            │ JIT Capability Broker│
            └────────────┬─────────┘
                         │
                         │ Short-lived Credential Request
                         ▼
        ┌────────────────────────────────┐
        │ Client Key Infrastructure      │
        │ (Fireblocks / Utila / AWS KMS) │
        └────────────────────────────────┘
```

Secrets never enter the agent’s reasoning context.
Vault never becomes the custodian.

---

## Status

This repository is in **design and scaffolding** phase.

No custody functionality is live here yet.

---

## License

This repository is **proprietary and not open source**.

All rights reserved © Sigil Core.

No portion of this codebase may be copied, modified, distributed, or deployed without explicit written permission from Sigil Core.

Access to this repository does not grant any license to use the software in production or commercial environments unless separately authorized.

---

## Documentation

Full technical documentation and integration guides are coming soon.

→ **https://docs.sigilcore.com**
