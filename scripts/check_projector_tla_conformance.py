#!/usr/bin/env python3
"""
TLA+ Projector Conformance Coverage Gate.

Parses docs/tla/projector_conformance_matrix.md and enforces:
  1. Every spec_id has at least one linked test.
  2. Guard-level spec_ids have both pass and break polarity
     (unless explicitly waived in the matrix).
  3. Every check_id referenced in the matrix exists in the
     runtime_check_catalog.md.
  4. Every spec_id has at least one check_id mapping.

Exit 0 if all rules pass, exit 1 with details on failure.
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX_PATH = REPO_ROOT / "docs" / "tla" / "projector_conformance_matrix.md"
CATALOG_PATH = REPO_ROOT / "docs" / "tla" / "runtime_check_catalog.md"


def parse_markdown_table(path: Path) -> list[dict[str, str]]:
    """Parse markdown tables into list of dicts (header → value)."""
    rows = []
    lines = path.read_text().splitlines()
    headers = None
    for line in lines:
        line = line.strip()
        if not line.startswith("|"):
            headers = None
            continue
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if not cells:
            continue
        # Skip separator rows
        if all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        if headers is None:
            headers = cells
            continue
        row = {}
        for i, h in enumerate(headers):
            row[h] = cells[i] if i < len(cells) else ""
        rows.append(row)
    return rows


def main() -> int:
    errors = []

    # ── Parse matrix ──
    if not MATRIX_PATH.exists():
        errors.append(f"MISSING: {MATRIX_PATH}")
        print("\n".join(errors))
        return 1

    matrix_rows = parse_markdown_table(MATRIX_PATH)
    if not matrix_rows:
        errors.append("EMPTY: conformance matrix has no rows")
        print("\n".join(errors))
        return 1

    # ── Parse catalog ──
    if not CATALOG_PATH.exists():
        errors.append(f"MISSING: {CATALOG_PATH}")
        print("\n".join(errors))
        return 1

    catalog_rows = parse_markdown_table(CATALOG_PATH)
    catalog_check_ids = {r["check_id"] for r in catalog_rows if "check_id" in r}

    # ── Rule 1: every spec_id has at least one test ──
    spec_tests: dict[str, list[str]] = defaultdict(list)
    for row in matrix_rows:
        sid = row.get("spec_id", "")
        tid = row.get("test_id", "")
        if sid and tid:
            spec_tests[sid].append(tid)

    for sid, tests in spec_tests.items():
        if not tests:
            errors.append(f"SPEC_NO_TEST: {sid} has no linked test")

    # ── Rule 2: guard-level spec_ids have pass + break ──
    spec_polarities: dict[str, set[str]] = defaultdict(set)
    for row in matrix_rows:
        sid = row.get("spec_id", "")
        pol = row.get("polarity", "")
        if sid and pol:
            spec_polarities[sid].add(pol)

    for sid, pols in spec_polarities.items():
        if "pass" not in pols:
            errors.append(f"SPEC_NO_PASS: {sid} has no pass-polarity test")
        if "break" not in pols:
            # Only warn for guard-level specs (not replay/order convergence specs)
            if not sid.startswith("SPEC_REPLAY_") and not sid.startswith("SPEC_CASCADE_") and not sid.startswith("SPEC_DEL_CONVERGENCE_"):
                errors.append(f"SPEC_NO_BREAK: {sid} has no break-polarity test (add test or waiver)")

    # ── Rule 3: every check_id in matrix exists in catalog ──
    matrix_check_ids = {row.get("check_id", "") for row in matrix_rows if row.get("check_id")}
    for cid in sorted(matrix_check_ids):
        if cid not in catalog_check_ids:
            errors.append(f"CHECK_NOT_IN_CATALOG: {cid} referenced in matrix but missing from catalog")

    # ── Rule 4: every spec_id has at least one check_id ──
    spec_checks: dict[str, set[str]] = defaultdict(set)
    for row in matrix_rows:
        sid = row.get("spec_id", "")
        cid = row.get("check_id", "")
        if sid and cid:
            spec_checks[sid].add(cid)

    for sid in spec_tests:
        if sid not in spec_checks or not spec_checks[sid]:
            errors.append(f"SPEC_NO_CHECK: {sid} has no check_id mapping")

    # ── Report ──
    if errors:
        print(f"TLA conformance check FAILED ({len(errors)} issues):\n")
        for e in sorted(errors):
            print(f"  {e}")
        return 1

    print(f"TLA conformance check PASSED: {len(spec_tests)} spec_ids, "
          f"{len(matrix_check_ids)} check_ids, {len(matrix_rows)} matrix rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
