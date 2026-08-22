#!/usr/bin/env python3
"""Prove the decision literal gate fails on a planted violation."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


GATE = Path(__file__).resolve().parents[1] / "scripts" / "decision_literal_gate.py"
WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "decision-literal-gate.yml"
BLOCKING_WORKFLOW_COMMAND = "run: python3 scripts/decision_literal_gate.py --blocking"
ADVISORY_WORKFLOW_COMMAND = "run: python3 scripts/decision_literal_gate.py"
LITERAL = "ALLOW" + "ED"


def run(root: Path, blocking: bool) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, str(GATE), "--root", str(root)]
    if blocking:
        command.append("--blocking")
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)


workflow_lines = [line.strip() for line in WORKFLOW.read_text(encoding="utf-8").splitlines()]
if workflow_lines.count(BLOCKING_WORKFLOW_COMMAND) != 1:
    raise SystemExit("Workflow must invoke the exact blocking literal-gate command once.")
if ADVISORY_WORKFLOW_COMMAND in workflow_lines:
    raise SystemExit("Workflow still invokes the advisory literal-gate command.")


with (
    tempfile.TemporaryDirectory(prefix="decision-literal-gate-") as temporary,
    tempfile.TemporaryDirectory(prefix="decision-literal-external-") as external_temporary,
):
    root = Path(temporary)
    source = root / "src"
    source.mkdir()
    config = {
        "version": 1,
        "scanPaths": ["."],
        "excludedPaths": ["decision-literal-allowlist.json"],
        "allowedOccurrences": [],
    }
    (root / "decision-literal-allowlist.json").write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8"
    )
    planted = source / "planted.py"
    planted.write_text('status = "DENIED"\n', encoding="utf-8")
    clean = run(root, True)
    if clean.returncode != 0:
        sys.stderr.write(clean.stderr)
        raise SystemExit("Clean control did not pass.")
    planted.write_text(f'status = "{LITERAL}"\n', encoding="utf-8")
    blocked = run(root, True)
    if (
        blocked.returncode != 1
        or "decision-literal-gate: 1 violation(s)" not in blocked.stderr
        or "src/planted.py:1:" not in blocked.stderr
    ):
        sys.stderr.write(blocked.stderr)
        raise SystemExit("Planted violation did not fail closed with path evidence.")
    advisory = run(root, False)
    if advisory.returncode != 0 or "1 violation(s) (advisory)" not in advisory.stderr:
        sys.stderr.write(advisory.stderr)
        raise SystemExit("Advisory mode did not report without blocking.")
    planted.write_text('status = "DENIED"\n', encoding="utf-8")
    extensionless = root / "CODEOWNERS"
    extensionless.write_text(f"* @{LITERAL}\n", encoding="utf-8")
    extensionless_result = run(root, True)
    if extensionless_result.returncode != 1 or "CODEOWNERS:1:" not in extensionless_result.stderr:
        sys.stderr.write(extensionless_result.stderr)
        raise SystemExit("Extensionless tracked text was not scanned.")
    extensionless.unlink()
    external = Path(external_temporary) / "outside.txt"
    external.write_text(f"{LITERAL}\n", encoding="utf-8")
    (root / "outside-link").symlink_to(external)
    escaped = run(root, True)
    if escaped.returncode != 2 or "Decision literal file escapes repository root." not in escaped.stderr:
        sys.stderr.write(escaped.stderr)
        raise SystemExit("External symlink did not fail with a controlled diagnostic.")
    print("decision-literal-gate-proof: clean, planted, extensionless, and symlink controls pass")
