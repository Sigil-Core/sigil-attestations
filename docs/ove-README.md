# Open Venture Engine (OVE)

*A fully autonomous Agentic Venture Capital stack secured by deterministic Intent Attestation enforcement.*

[![Status](https://img.shields.io/badge/status-active--development-black)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)
[![Security](https://img.shields.io/badge/security-Intent--Attestation-green)](#)

[![Spec Version](https://img.shields.io/badge/spec-v0.x-blue)](#)

---

## Executive Summary

The **Open Venture Engine (OVE)** is a pre-wired, Web3-native infrastructure stack that allows anyone to deploy a fully autonomous Venture Capital agent.

OVE aggregates best-in-class execution primitives while structurally enforcing deterministic governance through Sigil’s execution firewall.

This ensures the agent cannot:

- Drain its own treasury
- Execute unauthorized trades
- Bypass fiduciary constraints
- Mutate infrastructure without policy approval

OVE is designed to demonstrate how autonomous capital deployment can operate within strict structural boundaries.

---

## Architecture Overview

OVE separates execution into three distinct layers:

### 🧠 The Brain
- **ELIZA / LangChain**
- Evaluates market conditions
- Proposes investments or yield strategies
- Generates structured transaction intent

### ⚙️ The Engine
- **Coinbase AgentKit**
- Handles wallet provisioning
- Formats EVM transactions
- Generates ERC-4337 UserOperations

- **[Sigil Sign](https://sign.sigilcore.com)**
- `@sigilcore/agent-hooks`
- Enforces deterministic `ASSURANCE.md` policy
- Issues short-lived Ed25519-signed **Intent Attestations** conforming to the `sigil-attestations` specification

No transaction may execute without a valid Intent Attestation.

---

## Human Oversight Layer

While OVE is designed for autonomous execution, optional human-in-the-loop oversight can be implemented via **Sigil Sentry** (mobile app, iOS / Android).

Sigil Sentry enables:

- Real-time approval notifications
- Execution monitoring
- Emergency pause controls
- Audit visibility

Human approval is additive — deterministic policy enforcement remains mandatory regardless of Sentry usage.

---

## Identity & Yield Stack

OVE integrates modern Web3 primitives:

- **[ERC-6551](https://eips.ethereum.org/EIPS/eip-6551)** — Token Bound Accounts (VC Agent is the NFT)
- **[Safe (Gnosis)](https://safe.global/)** — Treasury custody
- **[Superfluid](https://www.superfluid.finance/)** — Automated revenue streaming to the human GP
- **[ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)** — Account abstraction and programmable execution

All outbound execution must route through Sigil.

---

## The Sigil OS Independent Build Bounty

Building an Agentic VC this week? We are running an independent developer bounty parallel to ongoing ecosystem hackathons.

### The Challenge

The first developer or team to successfully route their ELIZA agent's transaction intents through the Sigil Sign API (utilizing the Open Venture Engine) will receive a $1,500 USDC grant.

**Note:** This is an independent grant issued directly by Sigil Core and is not affiliated with or sponsored by third-party hackathon organizers. Payout is contingent on a successful, verifiable API integration and Intent Attestation generation.

---

### Submission Deadline

All qualifying integrations must be submitted and verifiable on or before **March 18, 2026 at 23:59 UTC**.

Submissions after this deadline will not be eligible for the grant.

---

### Verification Criteria

To qualify for the $1,500 USDC grant, the submission must demonstrate:

1. A live or reproducible ELIZA-based agent integration.
2. A real `POST /v1/authorize` request to `https://sign.sigilcore.com`.
3. Successful receipt of a valid Ed25519-signed **Intent Attestation**.
4. The Intent Attestation being appended to a real EOA transaction or ERC-4337 UserOperation.
5. On-chain verification that the transaction was executed only after authorization.

Mocked responses, simulated attestations, or hardcoded JWTs will not qualify.

---

## How Intent Attestation Works

Before execution:

1. The agent proposes a transaction.
2. The transaction intent is sent to `POST https://sign.sigilcore.com/v1/authorize`.
3. Sigil evaluates the request against `ASSURANCE.md`.
4. If compliant, Sigil Sign returns a short-lived Ed25519-signed Intent Attestation conforming to the `sigil-attestations` specification.
5. The transaction is executed only if the attestation is appended.

If denied, the agent receives a deterministic JSON Rebound and must halt execution.

---

## Getting Started

```bash
git clone https://github.com/sigil-core/ove.git
cd ove
npm install

# Configure environment variables
cp .env.example .env

# Edit deterministic policy constraints
nano ASSURANCE.md

# Start the Agentic VC
npm run start
```

---

## Repository Structure

```
/contracts
    Smart contract templates (if applicable)

/agent
    Agent orchestration logic

/policy
    ASSURANCE.md examples

/integrations
    Sigil Sign + AgentKit adapters
```

---

## Who OVE Is For

- Autonomous Venture Capital experiments
- DAO treasury automation
- Onchain investment protocols
- Agentic yield strategies
- Web3-native governance tooling

---

## The Strategic Goal

OVE demonstrates that autonomous capital deployment does not require blind trust.

By structurally enforcing deterministic authorization through Sigil Sign, OVE proves:

- Autonomous agents can operate within fiduciary boundaries
- Governance can be cryptographically enforced
- Liability can be bounded by architecture
- Execution can be provably authorized before capital moves

---


## Related Repositories

- **sigil-sign** — Deterministic execution firewall (Intent Attestation issuer)
- **sigil-attestations** — Canonical Intent Attestation specification (Ed25519 JWT standard)
- **sigil-vault** — Non-custodial JIT capability broker for execution control
- **faf** — Fiduciary Agent Framework (legal-technical wrapper)

---

## Documentation

Full technical documentation and integration guides are coming soon.

→ **https://docs.sigilcore.com**
