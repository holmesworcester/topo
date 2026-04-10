#!/usr/bin/env python3
"""
Formal seam coverage gate.

Enforces:
  1. Every covered seam row references existing runtime seam paths and Verus
     mirror paths.
  2. Every non-module Verus source is indexed in the seam or supporting-module
     tables.
  3. Every runtime/state file that exposes a DecisionContext/Plan-style seam is
     indexed in the covered-seams table.
  4. Every covered seam row has non-empty Requires / Provides / Targeted Checks,
     uses known invariant keys, names cargo-verus verification, and names at
     least one real `cargo test --lib <filter>` target.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_PATH = REPO_ROOT / "docs" / "planning" / "FORMAL_SEAM_COVERAGE.md"
KNOWN_INVARIANTS = {"UCA", "ALB", "WC", "AMF", "ECP"}


def parse_markdown_tables(path: Path) -> list[tuple[list[str], list[dict[str, str]]]]:
    tables: list[tuple[list[str], list[dict[str, str]]]] = []
    headers: list[str] | None = None
    rows: list[dict[str, str]] = []

    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            if headers is not None:
                tables.append((headers, rows))
            headers = None
            rows = []
            continue

        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if not cells:
            continue
        if all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue

        if headers is None:
            headers = cells
            rows = []
            continue

        row: dict[str, str] = {}
        for idx, header in enumerate(headers):
            row[header] = cells[idx] if idx < len(cells) else ""
        rows.append(row)

    if headers is not None:
        tables.append((headers, rows))
    return tables


def extract_code_paths(cell: str) -> list[str]:
    return [match.strip() for match in re.findall(r"`([^`]+)`", cell)]


def path_spec_exists(spec: str) -> bool:
    if spec.endswith("/*"):
        base = REPO_ROOT / spec[:-2]
        return base.is_dir() and any(base.iterdir())
    return (REPO_ROOT / spec).exists()


def spec_covers_path(spec: str, relative_path: str) -> bool:
    if spec.endswith("/*"):
        return relative_path.startswith(spec[:-1])
    return relative_path == spec


def collect_non_module_verus_sources() -> list[str]:
    sources: list[str] = []
    root = REPO_ROOT / "verus-proofs" / "src"
    for path in root.rglob("*.rs"):
        if path.name in {"lib.rs", "mod.rs"}:
            continue
        sources.append(path.relative_to(REPO_ROOT).as_posix())
    return sorted(sources)


def collect_candidate_runtime_seams() -> list[str]:
    candidates: list[str] = []
    context_re = re.compile(r"\bDecisionContext\b")
    normalize_re = re.compile(r"\bfn\s+normalize_[A-Za-z0-9_]+\b")
    decide_re = re.compile(r"\bfn\s+decide_[A-Za-z0-9_]+\b")
    plan_re = re.compile(r"\b(?:enum|struct)\s+[A-Za-z0-9_]*Plan\b")

    for root_name in ("src/runtime", "src/state"):
        root = REPO_ROOT / root_name
        for path in root.rglob("*.rs"):
            text = path.read_text()
            has_context = bool(context_re.search(text) or normalize_re.search(text))
            has_plan = bool(decide_re.search(text) and plan_re.search(text))
            if has_context and has_plan:
                candidates.append(path.relative_to(REPO_ROOT).as_posix())

    return sorted(candidates)


def collect_lib_test_names() -> set[str]:
    try:
        output = subprocess.check_output(
            ["cargo", "test", "--lib", "--", "--list"],
            cwd=str(REPO_ROOT),
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:  # pragma: no cover - surfaced as gate failure
        raise RuntimeError(f"failed to list cargo lib tests: {exc}") from exc

    test_names: set[str] = set()
    for line in output.splitlines():
        if line.endswith(": test"):
            test_names.add(line[:-6].strip())
    return test_names


def extract_lib_test_filters(checks: str) -> list[str]:
    return re.findall(r"cargo test\b[^;\n]*?--lib\s+([A-Za-z0-9_:-]+)\s+--", checks)


def parse_invariant_keys(cell: str) -> list[str]:
    return [token.strip().strip("`") for token in cell.split(",") if token.strip()]


def main() -> int:
    errors: list[str] = []

    if not COVERAGE_PATH.exists():
        print(f"MISSING: {COVERAGE_PATH}")
        return 1

    tables = parse_markdown_tables(COVERAGE_PATH)
    seam_rows: list[dict[str, str]] | None = None
    support_rows: list[dict[str, str]] | None = None

    for headers, rows in tables:
        header_set = set(headers)
        if {
            "Area",
            "Runtime Seam",
            "Verus Mirror",
            "Requires",
            "Provides",
            "Targeted Checks",
        }.issubset(header_set):
            seam_rows = rows
        elif {"Area", "Verus Mirror", "Role", "Check"}.issubset(header_set):
            support_rows = rows

    if seam_rows is None:
        errors.append("MISSING_TABLE: covered seams table not found")
    if support_rows is None:
        errors.append("MISSING_TABLE: supporting proof modules table not found")
    if errors:
        print("\n".join(errors))
        return 1

    assert seam_rows is not None
    assert support_rows is not None

    seam_runtime_specs: list[str] = []
    indexed_verus_specs: list[str] = []

    lib_test_names = collect_lib_test_names()

    for row in seam_rows:
        area = row.get("Area", "").strip() or "<unknown>"
        runtime_specs = extract_code_paths(row.get("Runtime Seam", ""))
        verus_specs = extract_code_paths(row.get("Verus Mirror", ""))
        requires = row.get("Requires", "").strip()
        provides = row.get("Provides", "").strip()
        checks = row.get("Targeted Checks", "").strip()

        if not runtime_specs:
            errors.append(f"ROW_NO_RUNTIME_SEAM: {area}")
        if not verus_specs:
            errors.append(f"ROW_NO_VERUS_MIRROR: {area}")
        if not requires:
            errors.append(f"ROW_NO_REQUIRES: {area}")
        if not provides:
            errors.append(f"ROW_NO_PROVIDES: {area}")
        if not checks:
            errors.append(f"ROW_NO_CHECKS: {area}")
            continue

        if "cargo-verus verify" not in checks:
            errors.append(f"ROW_NO_VERUS_CHECK: {area}")

        test_filters = extract_lib_test_filters(checks)
        if not test_filters:
            errors.append(f"ROW_NO_LIB_TEST_FILTER: {area}")
        else:
            for test_filter in test_filters:
                if not any(test_filter in name for name in lib_test_names):
                    errors.append(
                        f"ROW_BAD_LIB_TEST_FILTER: {area} references '{test_filter}', "
                        "but no lib test name matches"
                    )

        for invariant in parse_invariant_keys(provides):
            if invariant not in KNOWN_INVARIANTS:
                errors.append(f"ROW_UNKNOWN_INVARIANT: {area} provides '{invariant}'")

        for spec in runtime_specs:
            seam_runtime_specs.append(spec)
            if not path_spec_exists(spec):
                errors.append(f"ROW_BAD_RUNTIME_PATH: {area} references missing path '{spec}'")

        for spec in verus_specs:
            indexed_verus_specs.append(spec)
            if not path_spec_exists(spec):
                errors.append(f"ROW_BAD_VERUS_PATH: {area} references missing path '{spec}'")

    for row in support_rows:
        area = row.get("Area", "").strip() or "<unknown>"
        checks = row.get("Check", "").strip()
        verus_specs = extract_code_paths(row.get("Verus Mirror", ""))

        if not verus_specs:
            errors.append(f"SUPPORT_NO_VERUS_MIRROR: {area}")
        for spec in verus_specs:
            indexed_verus_specs.append(spec)
            if not path_spec_exists(spec):
                errors.append(
                    f"SUPPORT_BAD_VERUS_PATH: {area} references missing path '{spec}'"
                )
        if "cargo-verus verify" not in checks:
            errors.append(f"SUPPORT_NO_VERUS_CHECK: {area}")

    for candidate in collect_candidate_runtime_seams():
        if not any(spec_covers_path(spec, candidate) for spec in seam_runtime_specs):
            errors.append(
                "UNCOVERED_RUNTIME_SEAM: "
                f"{candidate} exposes a DecisionContext/Plan seam but is not indexed"
            )

    indexed_verus = set(indexed_verus_specs)
    for source in collect_non_module_verus_sources():
        if source not in indexed_verus:
            errors.append(
                f"UNINDEXED_VERUS_SOURCE: {source} is not listed in seam or support tables"
            )

    if errors:
        print("\n".join(sorted(errors)))
        return 1

    print("PASS: formal seam coverage is internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
