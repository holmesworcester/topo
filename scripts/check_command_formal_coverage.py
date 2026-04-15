#!/usr/bin/env python3
"""
Command/projector formal coverage gate.

Enforces:
  1. Every repo command-entry file (`src/**/commands.rs`, `src/**/commands_api.rs`)
     is indexed in docs/planning/COMMAND_FORMAL_COVERAGE.md.
  2. Every row references existing runtime path(s) and existing Verus mirror
     path(s).
  3. Every row has non-empty Role / Targeted Checks, names cargo-verus verify,
     and names at least one real cargo test target or script path.
  4. The projector-family gate row exists so projector coverage remains part of
     the same maintained surface.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
COVERAGE_PATH = REPO_ROOT / "docs" / "planning" / "COMMAND_FORMAL_COVERAGE.md"


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


def collect_command_modules() -> list[str]:
    modules: list[str] = []
    root = REPO_ROOT / "src"
    for path in root.rglob("*.rs"):
        if path.name not in {"commands.rs", "commands_api.rs"}:
            continue
        modules.append(path.relative_to(REPO_ROOT).as_posix())
    return sorted(modules)


def collect_lib_test_names() -> set[str]:
    output = subprocess.check_output(
        ["cargo", "test", "--lib", "--", "--list"],
        cwd=str(REPO_ROOT),
        text=True,
        stderr=subprocess.DEVNULL,
    )
    test_names: set[str] = set()
    for line in output.splitlines():
        if line.endswith(": test"):
            test_names.add(line[:-6].strip())
    return test_names


def collect_integration_test_targets() -> set[str]:
    targets: set[str] = set()
    tests_dir = REPO_ROOT / "tests"
    for rs_file in tests_dir.glob("*.rs"):
        targets.add(rs_file.stem)
    for main_rs in tests_dir.glob("**/main.rs"):
        if main_rs.parent == tests_dir:
            continue
        targets.add(main_rs.parent.name)
    return targets


def extract_lib_test_filters(checks: str) -> list[str]:
    return re.findall(r"cargo test\b[^;\n]*?--lib\s+([A-Za-z0-9_:-]+)\s+--", checks)


def extract_bin_test_specs(checks: str) -> list[tuple[str, str]]:
    return re.findall(
        r"cargo test\b[^;\n]*?--bin\s+([A-Za-z0-9_:-]+)\s+([A-Za-z0-9_:-]+)\s+--", checks
    )


def extract_integration_test_targets(checks: str) -> list[str]:
    return re.findall(r"cargo test\b[^;\n]*?--test\s+([A-Za-z0-9_:-]+)\s+--", checks)


def extract_script_paths(checks: str) -> list[str]:
    return re.findall(r"(?:python3|bash)\s+(scripts/[A-Za-z0-9_./-]+)", checks)


def main() -> int:
    if not COVERAGE_PATH.exists():
        print(f"MISSING: {COVERAGE_PATH}")
        return 1

    tables = parse_markdown_tables(COVERAGE_PATH)
    coverage_rows: list[dict[str, str]] | None = None
    for headers, rows in tables:
        if {"Area", "Runtime Module", "Verus Mirror", "Role", "Targeted Checks"}.issubset(
            set(headers)
        ):
            coverage_rows = rows
            break

    if coverage_rows is None:
        print("MISSING_TABLE: command/projector coverage table not found")
        return 1

    errors: list[str] = []
    indexed_runtime_specs: list[str] = []
    lib_test_names = collect_lib_test_names()
    binary_test_names_by_target: dict[str, set[str]] = {}
    integration_test_targets = collect_integration_test_targets()
    saw_projector_gate = False

    for row in coverage_rows:
        area = row.get("Area", "").strip() or "<unknown>"
        runtime_specs = extract_code_paths(row.get("Runtime Module", ""))
        verus_specs = extract_code_paths(row.get("Verus Mirror", ""))
        role = row.get("Role", "").strip()
        checks = row.get("Targeted Checks", "").strip()

        if not runtime_specs:
            errors.append(f"ROW_NO_RUNTIME_MODULE: {area}")
        if not verus_specs:
            errors.append(f"ROW_NO_VERUS_MIRROR: {area}")
        if not role:
            errors.append(f"ROW_NO_ROLE: {area}")
        if not checks:
            errors.append(f"ROW_NO_CHECKS: {area}")
            continue

        if "cargo-verus verify" not in checks:
            errors.append(f"ROW_NO_VERUS_CHECK: {area}")

        test_filters = extract_lib_test_filters(checks)
        bin_test_specs = extract_bin_test_specs(checks)
        integration_targets = extract_integration_test_targets(checks)
        script_paths = extract_script_paths(checks)
        if not test_filters and not bin_test_specs and not integration_targets and not script_paths:
            errors.append(f"ROW_NO_TARGETED_CHECK: {area}")

        for test_filter in test_filters:
            if not any(test_filter in name for name in lib_test_names):
                errors.append(
                    f"ROW_BAD_LIB_TEST_FILTER: {area} references '{test_filter}', but no lib test name matches"
                )
        for bin_target, test_filter in bin_test_specs:
            if bin_target not in binary_test_names_by_target:
                try:
                    output = subprocess.check_output(
                        ["cargo", "test", "--bin", bin_target, "--", "--list"],
                        cwd=str(REPO_ROOT),
                        text=True,
                        stderr=subprocess.DEVNULL,
                    )
                except subprocess.CalledProcessError:
                    errors.append(
                        f"ROW_BAD_BIN_TARGET: {area} references '{bin_target}', but cargo test --bin {bin_target} -- --list failed"
                    )
                    continue
                names: set[str] = set()
                for line in output.splitlines():
                    if line.endswith(": test"):
                        names.add(line[:-6].strip())
                binary_test_names_by_target[bin_target] = names
            if not any(test_filter in name for name in binary_test_names_by_target.get(bin_target, set())):
                errors.append(
                    f"ROW_BAD_BIN_TEST_FILTER: {area} references '{test_filter}' in bin '{bin_target}', but no test name matches"
                )
        for target in integration_targets:
            if target not in integration_test_targets:
                errors.append(
                    f"ROW_BAD_INTEGRATION_TEST_TARGET: {area} references '{target}', but no integration target matches"
                )
        for script_path in script_paths:
            if not (REPO_ROOT / script_path).exists():
                errors.append(
                    f"ROW_BAD_SCRIPT_PATH: {area} references missing script '{script_path}'"
                )

        for spec in runtime_specs:
            indexed_runtime_specs.append(spec)
            if not (REPO_ROOT / spec).exists():
                errors.append(f"ROW_BAD_RUNTIME_PATH: {area} references missing path '{spec}'")
            if spec == "src/event_modules/mod.rs":
                saw_projector_gate = True
        for spec in verus_specs:
            if not (REPO_ROOT / spec).exists():
                errors.append(f"ROW_BAD_VERUS_PATH: {area} references missing path '{spec}'")

    for module in collect_command_modules():
        if module not in indexed_runtime_specs:
            errors.append(f"UNCOVERED_COMMAND_MODULE: {module} is not indexed")

    if not saw_projector_gate:
        errors.append("MISSING_PROJECTOR_GATE_ROW: src/event_modules/mod.rs must be indexed")

    if errors:
        print("\n".join(sorted(errors)))
        return 1

    print("PASS: command/projector formal coverage is internally consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
