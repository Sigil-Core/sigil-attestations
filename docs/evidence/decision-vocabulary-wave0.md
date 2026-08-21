# Decision vocabulary Wave 0 evidence

Baseline: `origin/main` at `e0d8bf7cb6fa2156781c5e381be0f87f6a59f58e`.

Method: a case-sensitive search over every Git text blob at the baseline found
one `APPROVED` occurrence and zero `ALLOWED` occurrences. The table accounts
for the complete baseline. Classifications use the closed set from the design.

| Baseline path | Occurrence | Classification | Action |
| --- | --- | --- | --- |
| `docs/sign-README.md` | `"status": "APPROVED",` | gate-decision | Retain during Wave 1; replace after the emitter flip in the Wave 4 sweep. |

Totals at baseline: gate-decision 1; hold-status 0;
foreign-domain 0. The current allowlist identifies the one retained or
canonicalized occurrence by exact path, literal, trimmed line, and count.

## Execution-authority classification

This repository contains zero entry points that consume a Sigil decision
response and authorize execution from its status. It therefore receives no
decision-capability or import/architecture gate in this program.

Repository-specific surfaces were checked. The attestation library verifies independently supplied proof bundles and tokens, but it does not consume the `APPROVED` or `ALLOWED` decision-response vocabulary or authorize an action from that response status.

A future decision-response consumer invalidates this zero-entry-point
classification and requires a new Phase 0 inventory before merge.

## Literal gate and forced-failure proof

The advisory command is
`python3 scripts/decision_literal_gate.py`. It scans declared text surfaces,
reports unknown occurrences, and exits zero in Wave 1. The same command with
`--blocking` fails closed. The planted proof at
`tests/decision_literal_gate_proof.py` demonstrates a clean blocking pass, a
planted blocking failure with path evidence, and an advisory report.

## Security-seam classification

Trigger map version 1.1 classifies this diff as security-seam because
`.github/workflows/decision-literal-gate.yml` matches
`.github/workflows/**`. The minimality ladder is off. The final exact-head
review must use the security-seam gate.
