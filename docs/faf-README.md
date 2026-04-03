# Fiduciary Agent Framework (FAF)

*A legal-to-technical bridge that wraps autonomous AI agents in LLC structures enforced by deterministic Intent Attestations.*

[![Status](https://img.shields.io/badge/status-active--development-black)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Security](https://img.shields.io/badge/security-Deterministic--Governance-green)](#)

[![Spec Version](https://img.shields.io/badge/spec-v0.x-blue)](#)

---

## Executive Summary

The **Fiduciary Agent Framework (FAF)** is an open-source governance standard that allows founders, General Partners (GPs), DAOs, and enterprises to deploy autonomous AI agents without assuming unlimited personal liability.

FAF converts stochastic AI behavior into structurally bounded fiduciary execution through:

- Legal entity wrapping  
- Deterministic policy enforcement (`warranty.md`)
- Cryptographically signed **Intent Attestations**  
- Credential sequestration via Sigil infrastructure  

FAF ensures that compliance is enforced *before execution*, not after loss.

---

## The Liability Void

AI agents do not possess legal personhood.

As a result, the human founder, GP, or corporate officer carries **100% of the fiduciary liability** for any action executed by an autonomous system.

If an agent:

- Hallucinates  
- Is prompt-injected  
- Violates regulatory constraints  
- Exceeds treasury mandates  
- Leaks credentials  
- Executes unauthorized transactions  

…the human operator is legally exposed.

FAF closes this liability gap by making compliance a property of system architecture — not a hope about agent alignment.

---

## The Doctrine of Structural Trust

> Safety is not a property of prompts.  
> Safety is a property of architecture.

Under FAF:

- AI agents **never hold private keys**  
- AI agents **never see raw API credentials**  
- AI agents **cannot execute without deterministic authorization**  
- High-stakes actions must route through a policy enforcement layer  

All execution routes through **[Sigil Sign](https://sign.sigilcore.com)** and is evaluated against a deterministic `warranty.md` policy.

Execution only proceeds if the action carries a valid **Intent Attestation**.

---

## How FAF Works

### 1. The Legal Wrapper

The human founder establishes a legal entity (e.g., Wyoming DAO LLC) using open-source templates provided in this repository.

The operating agreement defines:

- Scope of autonomous authority  
- Spend limits  
- Risk tolerance  
- Compliance requirements  
- Human override conditions  

This document establishes fiduciary boundaries.

---

### 2. The `warranty.md` Policy Layer

The GP translates legal constraints into deterministic, machine-readable rules inside `warranty.md`.

Example:

```md
# warranty.md

- Do not invest more than 5 ETH per token.
- Only transact on allowlisted chainIds.
- Never execute transactions to non-whitelisted addresses.
- Require human approval for transfers > 10 ETH.
- Reject transactions exceeding defined daily treasury cap.
```

This file becomes the enforceable contract between the agent and the execution layer.

---

### 3. Deterministic Interception

The agent’s runtime must route high-stakes actions through Sigil infrastructure:

- Wallet transfers  
- Smart contract writes  
- ERC-4337 UserOperations  
- Treasury deployments  
- Credential injection requests  
- Infrastructure mutations  

Direct execution is structurally blocked.

---

### 4. Intent Attestation (Cryptographic Enforcement)

If the proposed action complies with `warranty.md`, Sigil Sign returns a short-lived, Ed25519-signed **Intent Attestation** (JWT).

The attestation:

- Binds to a specific `chainId`  
- Binds to a specific `txCommit` (EOA) or `userOpHash` (ERC-4337)  
- Expires in ≤ 60 seconds  
- Uses issuer `sigil-core`  
- Uses audience `sigil-sign`  

If denied, Sigil returns a deterministic JSON Rebound:

```json
{
  "status": "DENIED",
  "error_code": "SIGIL_POLICY_VIOLATION_04",
  "message": "Transaction exceeds defined treasury limit.",
  "intent_attestation": null
}
```

This guarantees compliance **before execution**, not after capital moves.

---

## Structural Guarantees

Under FAF:

- Agents cannot drain treasuries via prompt injection.
- Agents cannot exfiltrate secrets.
- Agents cannot mutate infrastructure without authorization.
- Every approved action is cryptographically provable.
- Every denied action is deterministically blocked.

FAF transforms autonomous agents into governed fiduciary instruments.

---

## Security Model

FAF operates under a **deny-by-default execution model**.

Core principles:

- No private keys reside inside AI model context.
- No raw API credentials are exposed to agent reasoning layers.
- All high-stakes actions require deterministic pre-execution authorization.
- Authorization decisions are cryptographically signed and time-bound.
- Policy enforcement occurs *before* on-chain execution.

FAF assumes that language models are probabilistic and potentially adversarially influenced. Therefore, governance enforcement is externalized into deterministic infrastructure rather than embedded in prompts.

---

## Threat Model Summary

| Threat Vector | Risk | Mitigation via FAF Architecture |
|--------------|------|----------------------------------|
| Prompt Injection | Agent executes unintended or malicious action | Deterministic pre-execution authorization via Sigil Sign |
| Treasury Drain | Excess capital deployment beyond mandate | `warranty.md` enforced spend limits |
| Privilege Escalation | Agent exceeds defined authority | Deny-by-default policy enforcement |
| Secret Exfiltration | API keys or private keys exposed to agent | Credential sequestration via Sigil Vault |
| Infrastructure Mutation | Unauthorized infra or credential changes | Mandatory interception of high-stakes actions |
| Replay / Reuse | Reuse of prior authorization | Short-lived, commit-bound Intent Attestations |

FAF assumes that models may hallucinate or be adversarially influenced. Therefore, enforcement is externalized into deterministic infrastructure rather than trusting internal alignment.

---
---

## Repository Structure

```
/legal-templates
    Standardized operating agreements (e.g., Wyoming DAO LLC)

/policy-templates
    Boilerplate warranty.md templates for:
        - Treasury management
        - DeFi strategies
        - Venture deployment
        - Governance voting
        - Yield farming

/examples
    Sample agent integration flows
```

---

## Who FAF Is For

- Agentic Venture Capital funds  
- Autonomous hedge funds  
- DAO treasuries  
- AI-native startups  
- Enterprise automation teams  
- Founders deploying autonomous financial agents  

---

## Relationship to Sigil Ecosystem

FAF operates within the broader Sigil governance architecture:

- **Sigil Sign** → Deterministic execution firewall  
- **Sigil Vault** → Just-in-time credential sequestration  
- **Sigil Command** → Mobile human-in-the-loop approval & monitoring interface (iOS / Android)  
- **Sigil Anchor** → Hardware execution residency (future phase)  
- **sigil-attestations** → Canonical Intent Attestation specification (Ed25519 JWT standard)  

---

### Cross‑Repository Architecture

FAF is designed to integrate directly with:

- **[Open Venture Engine (OVE)](https://github.com/sigil-core/ove)** — Agentic VC boilerplate secured by Intent Attestation enforcement.

OVE demonstrates a practical implementation of FAF in a live autonomous capital deployment context.

Developers building with OVE inherit the governance guarantees defined in FAF.

---

## Documentation

Full technical documentation and integration guides are coming soon.

→ **https://docs.sigilcore.com**
