#!/usr/bin/env python3
"""
TLA+ Projector Bidirectional (Bijection) Coverage Gate.

Enforces the "vice versa" rule:
  1. Every TLA guard referenced in projector_spec.md has at least one
     runtime check_id in the catalog.
  2. Every runtime check_id in the catalog maps to a tla_guard_id
     (or explicit NON_MODELED:: waiver).
  3. Every check_id in the catalog has at least one linked test row
     in the conformance matrix.
  4. Waivers (NON_MODELED::) are counted and reported.

Exit 0 if all rules pass, exit 1 with details on failure.
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "docs" / "tla" / "projector_spec.md"
CATALOG_PATH = REPO_ROOT / "docs" / "tla" / "runtime_check_catalog.md"
MATRIX_PATH = REPO_ROOT / "docs" / "tla" / "projector_conformance_matrix.md"


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


    # Names matching Inv\w+ that are not TLA+ guard identifiers
NOT_GUARDS = {
    "Invariant",       # generic TLA+ keyword
    "Invariants",      # generic TLA+ keyword
    "InviteAccepted",  # event type name, not a guard
}


def extract_tla_guards_from_spec(path: Path) -> set[str]:
    """Extract all Inv* guard names from the projector_spec.md invariant tables."""
    guards = set()
    text = path.read_text()
    # Match Inv* identifiers in table cells and inline references
    for m in re.finditer(r'\bInv\w+\b', text):
        name = m.group()
        if name not in NOT_GUARDS:
            guards.add(name)
    return guards


def main() -> int:
    errors = []
    waivers = []

    for p in [SPEC_PATH, CATALOG_PATH, MATRIX_PATH]:
        if not p.exists():
            errors.append(f"MISSING: {p}")
    if errors:
        print("\n".join(errors))
        return 1

    # ── Parse files ──
    spec_guards = extract_tla_guards_from_spec(SPEC_PATH)
    catalog_rows = parse_markdown_table(CATALOG_PATH)
    matrix_rows = parse_markdown_table(MATRIX_PATH)

    # Build catalog maps
    catalog_by_check: dict[str, str] = {}  # check_id → tla_guard_id
    guard_to_checks: dict[str, set[str]] = defaultdict(set)

    for row in catalog_rows:
        cid = row.get("check_id", "")
        gid = row.get("tla_guard_id", "")
        if cid:
            catalog_by_check[cid] = gid
            if not gid:
                pass  # will be caught by Rule 2
            elif gid.startswith("NON_MODELED::"):
                waivers.append((cid, gid))
            else:
                guard_to_checks[gid].add(cid)

    # Build matrix: check_id → test_ids
    check_to_tests: dict[str, list[str]] = defaultdict(list)
    for row in matrix_rows:
        cid = row.get("check_id", "")
        tid = row.get("test_id", "")
        if cid and tid and tid != "—":
            check_to_tests[cid].append(tid)

    # ── Rule 1: every TLA guard has at least one check_id ──
    for guard in sorted(spec_guards):
        if guard not in guard_to_checks or not guard_to_checks[guard]:
            errors.append(f"GUARD_NO_CHECK: TLA guard {guard} has no runtime check_id mapped to it")

    # ── Rule 2: every check_id maps to a valid guard or waiver ──
    for cid in sorted(catalog_by_check):
        gid = catalog_by_check[cid]
        if not gid:
            errors.append(f"CHECK_NO_GUARD: {cid} has no tla_guard_id mapping")
        elif not gid.startswith("NON_MODELED::") and gid not in spec_guards:
            errors.append(f"CHECK_UNKNOWN_GUARD: {cid} maps to '{gid}' which is not a known TLA guard")

    # ── Rule 3: every check_id has at least one linked test ──
    for cid in sorted(catalog_by_check):
        if cid not in check_to_tests or not check_to_tests[cid]:
            errors.append(f"CHECK_NO_TEST: {cid} has no linked test in conformance matrix")

    # ── Report ──
    if errors:
        print(f"Bijection check FAILED ({len(errors)} issues):\n")
        for e in sorted(errors):
            print(f"  {e}")
        if waivers:
            print(f"\n  Waivers ({len(waivers)}):")
            for cid, gid in sorted(waivers):
                print(f"    {cid} → {gid}")
        return 1

    print(f"Bijection check PASSED: {len(spec_guards)} TLA guards, "
          f"{len(catalog_by_check)} check_ids, {len(waivers)} waivers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
