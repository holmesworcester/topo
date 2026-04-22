#!/usr/bin/env bash
# check_projection_write_sites.sh — CI gate for projection-table writes.
#
# Invariant: every production (non-test, non-sim) write to a projection-tracked
# table happens through the apply engine (src/state/projection/apply/) OR a
# specific, whitelisted signer/schema site. Writes that appear elsewhere break
# the refinement assumption that every projector's decision determines what
# rows exist — including the access-control claim that "no peer can write a
# key_secrets row for a non-invited peer."
#
# Coverage:
#   - INSERT (including INSERT OR IGNORE, INSERT OR REPLACE)
#   - UPDATE
#   - DELETE FROM
# Against:
#   - A curated list of projection-output tables (see TABLES below).
# Scopes skipped:
#   - Inside #[cfg(test)] blocks (brace-depth parsed).
#   - src/sim/ (simulation harness; no daemon runtime impact).
#   - src/testutil/ (test helpers).
#   - tests/ (integration tests).
# Allow-list:
#   - src/state/projection/apply/*.rs (the executor; valid_events/rejected_events/
#     blocked_events/blocked_event_deps write sites).
#   - src/state/projection/signer.rs (valid_events pre-mark during signer stage).
#   - src/state/projection/apply/write_exec.rs (dynamic-SQL executor;
#     table name is substituted via format! and this script's grep won't
#     even match it, but listed for completeness).
#   - src/state/db/schema.rs (DDL only).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/src"

python3 - "$SRC" <<'PYEOF'
import sys, re, os

src_dir = sys.argv[1]

# Access-control-critical projection tables. Writes to these tables must go
# through the apply engine or a whitelisted apply-adjacent site.
#
# This set is intentionally narrow — it covers tables that the "user cannot
# read messages unless invited" theorem's proof chain depends on. Additional
# tables can be added as their seam-level proofs are tightened.
TABLES = {
    # Content-key availability: the load-bearing table for decryption gate.
    "key_secrets",
    # Transport-trust identity: peers_shared row existence is the gate for
    # authorized transport (proved by the revocation step 3 seam).
    "peers_shared",
}

# Files allowed to contain production writes to the tables above.
# Paths are relative to the repo root (posix separators).
ALLOWED_WRITERS = {
    # Apply executor / signer stage.
    "src/state/projection/apply/backend.rs",      # valid_events
    "src/state/projection/apply/stages.rs",       # rejected_events, blocked_events, blocked_event_deps
    "src/state/projection/apply/write_exec.rs",   # dynamic executor (table via format!)
    "src/state/projection/signer.rs",             # valid_events pre-mark
    # Schema / migrations (DDL is not written as INSERT/UPDATE/DELETE, but list for completeness).
    "src/state/db/schema.rs",
}

# Skip these entire subtrees (not production-facing).
SKIP_DIRS = ("src/sim", "src/testutil")

# Files whose entire content is test (dedicated *_tests.rs or tests.rs files).
def is_test_only_file(rel_path: str) -> bool:
    base = rel_path.rsplit("/", 1)[-1]
    if base == "tests.rs":
        return True
    if base.endswith("_test.rs") or base.endswith("_tests.rs"):
        return True
    # Any file under a .../tests/ directory.
    if "/tests/" in "/" + rel_path:
        return True
    return False

# Regexes. Each captures the table name in group 2.
patterns = {
    "INSERT": re.compile(
        r"\bINSERT\s+(?:OR\s+(?:IGNORE|REPLACE|ROLLBACK|ABORT|FAIL)\s+)?INTO\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE,
    ),
    "UPDATE": re.compile(
        r"\bUPDATE\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE,
    ),
    "DELETE": re.compile(
        r"\bDELETE\s+FROM\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE,
    ),
}

errors = []
ok_count = 0

def is_skipped_dir(rel_path: str) -> bool:
    return any(rel_path.startswith(d + "/") or rel_path.startswith(d + os.sep) for d in SKIP_DIRS)

for root, dirs, files in os.walk(src_dir):
    dirs[:] = [d for d in dirs if d not in ("target", "vendor")]
    for fname in files:
        if not fname.endswith(".rs"):
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, os.path.dirname(src_dir)).replace(os.sep, "/")

        if is_skipped_dir(rel) or is_test_only_file(rel):
            continue

        with open(fpath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        # Brace-depth #[cfg(test)] skipping.
        in_test_block = False
        test_brace_depth = 0
        cfg_test_pending = False

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            if "#[cfg(test)]" in stripped:
                cfg_test_pending = True
                continue

            if cfg_test_pending and "{" in stripped and (
                stripped.startswith("mod ")
                or stripped.startswith("fn ")
                or stripped.startswith("impl ")
                or stripped.startswith("pub fn ")
                or stripped.startswith("pub(crate) fn ")
                or stripped.startswith("pub(super) fn ")
            ):
                in_test_block = True
                test_brace_depth = stripped.count("{") - stripped.count("}")
                cfg_test_pending = False
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue

            if in_test_block:
                test_brace_depth += stripped.count("{") - stripped.count("}")
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue

            for op, pat in patterns.items():
                m = pat.search(line)
                if m:
                    table = m.group(1).lower()
                    if rel in ALLOWED_WRITERS:
                        ok_count += 1
                        print(f"OK: {op} {table} at {rel}:{lineno}")
                    else:
                        errors.append(
                            f"ERROR: {op} on projection-tracked table '{table}' at {rel}:{lineno}: {line.rstrip()}"
                        )

# Second pass: forbid DSL-level key_secrets construction via the generic
# `WriteOp::InsertOrIgnore { ... table: "key_secrets", ... }` pattern. The
# typed variant `WriteOp::InsertKeySecret(KeySecretsRow)` is the sole
# legitimate construction path.
#
# Uses DOTALL so the regex spans newlines: real code puts "WriteOp::InsertOrIgnore {"
# on one line and `table: "key_secrets",` on a subsequent line. The `[^}]*?`
# non-greedy body match stays within a single struct literal so a later
# WriteOp construction in the same file doesn't spuriously match across
# struct boundaries.
dsl_pattern = re.compile(
    r'WriteOp::InsertOrIgnore\s*\{[^}]*?table\s*:\s*"key_secrets"',
    re.DOTALL,
)
# Anchor line number by matching the start of `WriteOp::InsertOrIgnore`.
writeop_start = re.compile(r"WriteOp::InsertOrIgnore")
for root, dirs, files in os.walk(src_dir):
    dirs[:] = [d for d in dirs if d not in ("target", "vendor")]
    for fname in files:
        if not fname.endswith(".rs"):
            continue
        fpath = os.path.join(root, fname)
        rel = os.path.relpath(fpath, os.path.dirname(src_dir)).replace(os.sep, "/")
        if is_skipped_dir(rel) or is_test_only_file(rel):
            continue
        with open(fpath, encoding="utf-8", errors="replace") as f:
            text = f.read()
        # Build a per-byte-offset map to line numbers so matches in the
        # multiline regex can be attributed to a specific source line.
        line_starts = [0]
        for i, c in enumerate(text):
            if c == "\n":
                line_starts.append(i + 1)
        def offset_to_line(off):
            # Binary search for the line.
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= off:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1
        # Build a "is this byte inside a #[cfg(test)] block" mask using the
        # same brace-depth approach as the first pass.
        cfg_test_range = set()
        in_test_block = False
        test_brace_depth = 0
        cfg_test_pending = False
        for lineno, line in enumerate(text.splitlines(keepends=True), 1):
            stripped = line.strip()
            if "#[cfg(test)]" in stripped:
                cfg_test_pending = True
                continue
            if cfg_test_pending and "{" in stripped and (
                stripped.startswith("mod ") or stripped.startswith("fn ")
                or stripped.startswith("impl ") or stripped.startswith("pub fn ")
                or stripped.startswith("pub(crate) fn ")
                or stripped.startswith("pub(super) fn ")
            ):
                in_test_block = True
                test_brace_depth = stripped.count("{") - stripped.count("}")
                cfg_test_pending = False
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue
            if in_test_block:
                test_brace_depth += stripped.count("{") - stripped.count("}")
                cfg_test_range.add(lineno)
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0
                continue
        for m in dsl_pattern.finditer(text):
            # Attribute the match to the line where `WriteOp::InsertOrIgnore` starts.
            start_line = offset_to_line(m.start())
            if start_line in cfg_test_range:
                continue
            # Reconstruct a short snippet for the error message.
            snippet = text[m.start():m.end()].replace("\n", " \\n ")
            if len(snippet) > 160:
                snippet = snippet[:160] + "..."
            errors.append(
                f"ERROR: DSL-level key_secrets construction via WriteOp::InsertOrIgnore "
                f"at {rel}:{start_line}: {snippet}"
            )

if errors:
    print()
    for e in errors:
        print(e)
    print()
    print(f"Projection write-site invariant violated: {len(errors)} unexpected write(s).")
    print()
    print("Writes to projection-tracked tables must go through the apply engine")
    print("(src/state/projection/apply/*) or one of the other allowed writers:")
    for w in sorted(ALLOWED_WRITERS):
        print(f"  {w}")
    print()
    print("Test fixtures inside #[cfg(test)] blocks are exempt.")
    print("Simulation harness (src/sim/) and test utilities (src/testutil/) are exempt.")
    sys.exit(1)
else:
    print()
    print(f"Projection write-site invariant OK: {ok_count} allowed write(s) in production code, 0 unexpected.")
PYEOF
