#!/usr/bin/env python3
"""Report unclassified Sigil decision literals on declared text surfaces."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


LITERALS = {"APPRO" + "VED", "ALLOW" + "ED"}
TOKEN = re.compile(r"(?<![A-Z0-9_])(APPRO" + r"VED|ALLOW" + r"ED)(?![A-Z0-9_])")
TEXT_SUFFIXES = {
    ".cfg", ".conf", ".css", ".env", ".example", ".html", ".ini",
    ".js", ".json", ".jsx", ".md", ".mjs", ".mts", ".py", ".sh",
    ".sql", ".toml", ".ts", ".tsx", ".txt", ".yaml", ".yml",
}
TEXT_NAMES = {"Dockerfile", "LICENSE", "Makefile"}
SKIP_DIRS = {".git", ".venv", "__pycache__", "build", "coverage", "dist", "node_modules"}


def fail(message: str) -> "NoReturn":
    raise ValueError(message)


def relative_path(root: Path, value: object) -> str:
    if not isinstance(value, str) or not value:
        fail("Invalid decision literal allowlist schema.")
    candidate = (root / value).resolve()
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        fail("Decision literal path escapes repository root.")


def load_config(root: Path, path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("Invalid decision literal allowlist schema.")
    if not isinstance(config, dict) or set(config) != {
        "version", "scanPaths", "excludedPaths", "allowedOccurrences"
    }:
        fail("Invalid decision literal allowlist schema.")
    if config["version"] != 1 or not isinstance(config["scanPaths"], list) or not config["scanPaths"]:
        fail("Invalid decision literal allowlist schema.")
    if not isinstance(config["excludedPaths"], list) or not isinstance(config["allowedOccurrences"], list):
        fail("Invalid decision literal allowlist schema.")
    return config


def text_files(root: Path, scan_paths: list[object], exclusions: set[str]) -> list[Path]:
    files: set[Path] = set()
    for raw in scan_paths:
        relative = relative_path(root, raw)
        target = (root / relative).resolve()
        candidates = target.rglob("*") if target.is_dir() else [target]
        for candidate in candidates:
            if any(part in SKIP_DIRS for part in candidate.parts):
                continue
            if not candidate.is_file():
                continue
            repo_path = candidate.resolve().relative_to(root).as_posix()
            if repo_path in exclusions:
                continue
            if candidate.suffix.lower() in TEXT_SUFFIXES or candidate.name in TEXT_NAMES:
                files.add(candidate.resolve())
    if not files:
        fail("decision-literal-gate: no text files matched.")
    return sorted(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--config", default="decision-literal-allowlist.json")
    parser.add_argument("--blocking", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    config_path = (root / args.config).resolve()
    config = load_config(root, config_path)
    exclusions = {relative_path(root, value) for value in config["excludedPaths"]}
    allowances: dict[tuple[str, str, str], list[int]] = {}
    for entry in config["allowedOccurrences"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "literal", "expression", "expectedCount", "reason"}:
            fail("Invalid decision literal allowance entry.")
        path = relative_path(root, entry["path"])
        literal, expression, expected, reason = entry["literal"], entry["expression"], entry["expectedCount"], entry["reason"]
        if literal not in LITERALS or not isinstance(expression, str) or expression.strip() != expression:
            fail("Invalid decision literal allowance entry.")
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1 or not isinstance(reason, str) or not reason:
            fail("Invalid decision literal allowance entry.")
        key = (path, literal, expression)
        if key in allowances:
            fail("Duplicate decision literal allowance.")
        allowances[key] = [expected, 0]
    violations: list[str] = []
    files = text_files(root, config["scanPaths"], exclusions)
    for path in files:
        repo_path = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(lines, 1):
            expression = line.strip()
            for match in TOKEN.finditer(line):
                key = (repo_path, match.group(1), expression)
                if key in allowances:
                    allowances[key][1] += 1
                else:
                    violations.append(f"{repo_path}:{number}:{expression}")
    for (path, _literal, expression), (expected, actual) in allowances.items():
        if expected != actual:
            violations.append(f"{path}: expected {expected} occurrence(s) of {expression!r}, found {actual}")
    classified = sum(actual for _expected, actual in allowances.values())
    if violations:
        mode = "" if args.blocking else " (advisory)"
        print(f"decision-literal-gate: {len(violations)} violation(s){mode}", file=sys.stderr)
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1 if args.blocking else 0
    print(f"decision-literal-gate: {len(files)} files, {classified} classified occurrence(s), 0 violations")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
