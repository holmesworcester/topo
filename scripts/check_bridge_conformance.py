#!/usr/bin/env python3
"""Validate UnifiedBridge conformance matrix coverage.

Fails if bridge safety/security checks regress to TLC-only waivers or lose
required pass/break evidence in docs/tla/projector_conformance_matrix.md.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "tla" / "projector_conformance_matrix.md"
CATALOG_PATH = ROOT / "docs" / "tla" / "runtime_check_catalog.md"

LIVENESS_CHECK_IDS = {
    "CHK_BRIDGE_BOOTSTRAP_PROGRESS",
    "CHK_BRIDGE_UPGRADE_PROGRESS",
    "CHK_BRIDGE_SYNC_COMPLETION_PROGRESS",
}

DISALLOWED_WAIVERS = {
    "waiver:model_exercised_in_tlc",
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


def parse_bridge_check_ids_from_catalog(content: str) -> set[str]:
    ids: set[str] = set()
    row_pattern = re.compile(r"^\|\s*(CHK_BRIDGE_[A-Z0-9_]+)\s*\|")
    for line in content.splitlines():
        m = row_pattern.match(line.strip())
        if m:
            ids.add(m.group(1))
    return ids


def main() -> int:
    matrix_content = MATRIX_PATH.read_text(encoding="utf-8")
    catalog_content = CATALOG_PATH.read_text(encoding="utf-8")

    bridge_section = section_lines(matrix_content, "## UnifiedBridge Invariants")
    bridge_rows = parse_markdown_table_rows(bridge_section)
    bridge_rows = [r for r in bridge_rows if r["check_id"].startswith("CHK_BRIDGE_")]
    if not bridge_rows:
        print("No CHK_BRIDGE rows found in UnifiedBridge section.", file=sys.stderr)
        return 1

    errors: list[str] = []

    for row in bridge_rows:
        if row["polarity"] in DISALLOWED_WAIVERS:
            errors.append(
                f"Disallowed bridge waiver for {row['check_id']} ({row['spec_id']}): {row['polarity']}"
            )

    by_check: dict[str, list[dict[str, str]]] = {}
    for row in bridge_rows:
        by_check.setdefault(row["check_id"], []).append(row)

    expected_check_ids = parse_bridge_check_ids_from_catalog(catalog_content)
    missing_in_matrix = sorted(expected_check_ids - set(by_check.keys()))
    if missing_in_matrix:
        errors.append(
            "Missing CHK_BRIDGE coverage rows for: " + ", ".join(missing_in_matrix)
        )

    for check_id in sorted(expected_check_ids):
        rows = by_check.get(check_id, [])
        if not rows:
            continue

        non_waiver_rows = [r for r in rows if not r["polarity"].startswith("waiver:")]
        pass_rows = [r for r in non_waiver_rows if r["polarity"] == "pass" and r["test_id"] != "—"]
        break_rows = [r for r in non_waiver_rows if r["polarity"] == "break" and r["test_id"] != "—"]

        if not pass_rows:
            errors.append(f"{check_id} has no non-waiver pass evidence row.")

        if check_id not in LIVENESS_CHECK_IDS and not break_rows:
            errors.append(f"{check_id} has no non-waiver break evidence row.")

    if errors:
        print("UnifiedBridge conformance check failed:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 1

    print(
        f"UnifiedBridge conformance check passed for {len(expected_check_ids)} CHK_BRIDGE checks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

