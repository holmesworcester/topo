#!/usr/bin/env python3
"""Validate TransportCredentialLifecycle conformance matrix coverage.

Fails if TCL checks regress to integration-effect waivers or lose required
non-waiver pass/break evidence in docs/tla/projector_conformance_matrix.md.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "tla" / "projector_conformance_matrix.md"
CATALOG_PATH = ROOT / "docs" / "tla" / "runtime_check_catalog.md"

DISALLOWED_WAIVERS = {
    "waiver:integration_effect_only",
}


def parse_markdown_table_rows(lines: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in lines:
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 6:
            continue
        if cells[0] == "spec_id" or set(cells[0]) == {"-"}:
            continue
        rows.append(
            {
                "spec_id": cells[0],
                "source": cells[1],
                "check_id": cells[2],
                "layer": cells[3],
                "test_id": cells[4],
                "polarity": cells[5],
            }
        )
    return rows


def section_lines(content: str, section_header: str) -> list[str]:
    lines = content.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.strip() == section_header:
            start = idx + 1
            break
    if start is None:
        raise ValueError(f"missing section header: {section_header}")

    out: list[str] = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        out.append(line)
    return out


def parse_tcl_check_ids_from_catalog(content: str) -> set[str]:
    ids: set[str] = set()
    row_pattern = re.compile(r"^\|\s*(CHK_TCL_[A-Z0-9_]+)\s*\|")
    for line in content.splitlines():
        m = row_pattern.match(line.strip())
        if m:
            ids.add(m.group(1))
    return ids


def main() -> int:
    matrix_content = MATRIX_PATH.read_text(encoding="utf-8")
    catalog_content = CATALOG_PATH.read_text(encoding="utf-8")

    section = section_lines(matrix_content, "## TransportCredentialLifecycle Invariants")
    rows = parse_markdown_table_rows(section)
    rows = [r for r in rows if r["check_id"].startswith("CHK_TCL_")]
    if not rows:
        print("No CHK_TCL rows found in TCL section.", file=sys.stderr)
        return 1

    errors: list[str] = []
    for row in rows:
        if row["polarity"] in DISALLOWED_WAIVERS:
            errors.append(
                f"Disallowed TCL waiver for {row['check_id']} ({row['spec_id']}): {row['polarity']}"
            )

    by_check: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_check.setdefault(row["check_id"], []).append(row)

    expected = parse_tcl_check_ids_from_catalog(catalog_content)
    missing = sorted(expected - set(by_check.keys()))
    if missing:
        errors.append("Missing CHK_TCL coverage rows for: " + ", ".join(missing))

    for check_id in sorted(expected):
        crows = by_check.get(check_id, [])
        if not crows:
            continue
        non_waiver = [r for r in crows if not r["polarity"].startswith("waiver:")]
        pass_rows = [r for r in non_waiver if r["polarity"] == "pass" and r["test_id"] != "—"]
        break_rows = [r for r in non_waiver if r["polarity"] == "break" and r["test_id"] != "—"]
        if not pass_rows:
            errors.append(f"{check_id} has no non-waiver pass evidence row.")
        if not break_rows:
            errors.append(f"{check_id} has no non-waiver break evidence row.")

    if errors:
        print("TCL conformance check failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    print(f"TCL conformance check passed for {len(expected)} CHK_TCL checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

