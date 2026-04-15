#!/usr/bin/env python3
"""
Diff-aware formal mirror update gate.

Enforces:
  1. If a covered runtime command/seam/projector path changes, at least one
     mapped Verus mirror must also change in the same branch/worktree diff.
  2. The check includes committed changes on the branch, staged/unstaged
     changes, and untracked files.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SEAM_COVERAGE_PATH = REPO_ROOT / "docs" / "planning" / "FORMAL_SEAM_COVERAGE.md"
COMMAND_COVERAGE_PATH = REPO_ROOT / "docs" / "planning" / "COMMAND_FORMAL_COVERAGE.md"


def git_lines(args: list[str]) -> set[str]:
    output = subprocess.check_output(args, cwd=str(REPO_ROOT), text=True)
    return {line.strip() for line in output.splitlines() if line.strip()}


def changed_paths() -> set[str]:
    changed: set[str] = set()

    try:
        merge_base = (
            subprocess.check_output(
                ["git", "merge-base", "HEAD", "origin/master"],
                cwd=str(REPO_ROOT),
                text=True,
            )
            .strip()
        )
    except subprocess.CalledProcessError:
        merge_base = ""

    if merge_base:
        changed.update(git_lines(["git", "diff", "--name-only", f"{merge_base}...HEAD"]))

    changed.update(git_lines(["git", "diff", "--name-only", "HEAD"]))
    changed.update(git_lines(["git", "ls-files", "--others", "--exclude-standard"]))
    return changed


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


def load_runtime_to_verus_map(path: Path, runtime_header: str) -> list[tuple[str, list[str]]]:
    tables = parse_markdown_tables(path)
    for headers, rows in tables:
        if runtime_header not in headers or "Verus Mirror" not in headers:
            continue
        mappings: list[tuple[str, list[str]]] = []
        for row in rows:
            runtime_specs = extract_code_paths(row.get(runtime_header, ""))
            verus_specs = extract_code_paths(row.get("Verus Mirror", ""))
            if not runtime_specs or not verus_specs:
                continue
            for runtime_spec in runtime_specs:
                mappings.append((runtime_spec, verus_specs))
        return mappings
    raise RuntimeError(f"missing coverage table in {path}")


def runtime_spec_matches(spec: str, changed_path: str) -> bool:
    if spec.endswith("/*"):
        return changed_path.startswith(spec[:-1])
    if "*" in spec:
        return Path(changed_path).match(spec)
    return changed_path == spec


def main() -> int:
    changed = changed_paths()
    runtime_to_verus: list[tuple[str, list[str]]] = []
    runtime_to_verus.extend(load_runtime_to_verus_map(SEAM_COVERAGE_PATH, "Runtime Seam"))
    runtime_to_verus.extend(load_runtime_to_verus_map(COMMAND_COVERAGE_PATH, "Runtime Module"))

    errors: list[str] = []

    for path in sorted(changed):
        matched_verus: set[str] = set()
        for runtime_spec, verus_specs in runtime_to_verus:
            if runtime_spec == "event-module projectors":
                continue
            if runtime_spec_matches(runtime_spec, path):
                matched_verus.update(verus_specs)
        if not matched_verus:
            continue
        if not any(verus_path in changed for verus_path in matched_verus):
            mirrors = ", ".join(sorted(matched_verus))
            errors.append(
                f"MISSING_VERUS_MIRROR_UPDATE: {path} changed but no mapped Verus mirror changed ({mirrors})"
            )

    if errors:
        print("\n".join(errors))
        return 1

    print("PASS: covered runtime changes also updated their Verus mirrors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
