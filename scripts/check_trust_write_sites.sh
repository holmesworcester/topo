#!/usr/bin/env bash
# check_trust_write_sites.sh — CI gate for trust-table write-site invariant.
#
# Security invariant (AXIOM_TRUST_WRITES_REQUIRE_INVITE):
#   Every *production* (non-test) write to a trust table must be inside either:
#     (a) A projector processing a signed invite-chain event, or
#     (b) state/db/transport_trust.rs (the DB helper used by projectors).
#
# This script finds INSERT statements targeting trust tables in non-test source
# files and asserts they only appear in the allowed production write files.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/src"

# Files allowed to have production trust-table writes
ALLOWED_PEERS_SHARED=(
  "src/event_modules/peer_shared/queries.rs"
  "src/event_modules/workspace/queries.rs"
  "src/state/db/transport_trust.rs"
)
ALLOWED_INVITE_BOOTSTRAP=(
  "src/event_modules/workspace/queries.rs"
  "src/state/db/transport_trust.rs"
)
ALLOWED_PENDING_BOOTSTRAP=(
  "src/state/db/transport_trust.rs"
)

# Strategy: find INSERT write sites, then exclude lines that appear to be
# inside test modules by checking if the file is in testutil/ or ends in /tests.rs,
# or if the line context suggests it's inside a cfg(test) block.
#
# We use a Python script for accurate test-block detection.

python3 - "$SRC" <<'PYEOF'
import sys, re, os

src_dir = sys.argv[1]

# Allowed production write files (relative to repo root)
allowed = {
    "peers_shared": {
        "src/event_modules/peer_shared/queries.rs",
        "src/event_modules/workspace/queries.rs",
        "src/state/db/transport_trust.rs",
    },
    "invite_bootstrap_trust": {
        "src/event_modules/workspace/queries.rs",
        "src/state/db/transport_trust.rs",
    },
    "pending_invite_bootstrap_trust": {
        "src/state/db/transport_trust.rs",
    },
}

tables = list(allowed.keys())
insert_pattern = re.compile(r'INSERT\s+(OR\s+\w+\s+)?INTO\s+(' + '|'.join(tables) + r')\b', re.IGNORECASE)

errors = []

for root, dirs, files in os.walk(src_dir):
    # Skip target and vendor directories
    dirs[:] = [d for d in dirs if d not in ('target', 'vendor')]
    for fname in files:
        if not fname.endswith('.rs'):
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, os.path.dirname(src_dir))  # relative to repo root

        # Skip test-only files
        if 'testutil' in rel or rel.endswith('/tests.rs') or '/tests/' in rel:
            continue

        with open(fpath, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        # Track whether we are inside a #[cfg(test)] block
        # Heuristic: find #[cfg(test)], then next mod/function block and track braces.
        in_test_block = False
        test_brace_depth = 0
        cfg_test_pending = False

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            if '#[cfg(test)]' in stripped:
                cfg_test_pending = True
                continue

            if cfg_test_pending and ('{' in stripped) and (
                stripped.startswith('mod ') or
                stripped.startswith('fn ') or
                stripped.startswith('impl ') or
                stripped.startswith('pub fn ') or
                stripped.startswith('pub(crate) fn ')
            ):
                in_test_block = True
                test_brace_depth = stripped.count('{') - stripped.count('}')
                cfg_test_pending = False
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue

            if in_test_block:
                test_brace_depth += stripped.count('{') - stripped.count('}')
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue

            m = insert_pattern.search(line)
            if m:
                table = m.group(2).lower()
                allowed_set = allowed.get(table, set())
                if rel not in allowed_set:
                    errors.append(f"ERROR: unexpected {table} write site at {rel}:{lineno}: {line.rstrip()}")
                else:
                    print(f"OK: {table} write at {rel}:{lineno}")

if errors:
    print()
    for e in errors:
        print(e)
    print()
    print(f"Trust write-site invariant violated: {len(errors)} unexpected write location(s) found.")
    print("Allowed production write files:")
    for table, files in allowed.items():
        print(f"  {table}: {sorted(files)}")
    sys.exit(1)
else:
    print()
    print("Trust write-site invariant OK: all INSERT sites are in allowed production files.")
PYEOF
