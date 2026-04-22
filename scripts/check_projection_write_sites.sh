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

# Regexes with DOTALL so multiline SQL literals are caught.
# `\s+` in Python regex already matches newlines, but we use re.DOTALL
# to make `.` span newlines if it appears. Each captures the table name.
patterns = {
    "INSERT": re.compile(
        r"\bINSERT\s+(?:OR\s+(?:IGNORE|REPLACE|ROLLBACK|ABORT|FAIL)\s+)?INTO\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "UPDATE": re.compile(
        r"\bUPDATE\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "DELETE": re.compile(
        r"\bDELETE\s+FROM\s+(" + "|".join(sorted(TABLES)) + r")\b",
        re.IGNORECASE | re.DOTALL,
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
            text = f.read()

        # Build a (byte-offset-start, byte-offset-end-exclusive) set for
        # cfg(test) regions so multiline matches can be filtered.
        lines = text.splitlines(keepends=True)
        line_starts = [0]
        running = 0
        for l in lines:
            running += len(l)
            line_starts.append(running)

        def line_to_offset_range(lineno):
            # lineno is 1-based; returns (start, end) byte range for that line.
            i = lineno - 1
            if i < 0 or i >= len(lines):
                return (0, 0)
            return (line_starts[i], line_starts[i + 1])

        def offset_to_line(off):
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= off:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        cfg_test_lineset = set()
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
                cfg_test_lineset.add(lineno)
                if test_brace_depth <= 0:
                    in_test_block = False
                    test_brace_depth = 0

        # Scan the WHOLE FILE with DOTALL-aware patterns, so multiline
        # SQL literals (e.g., split across string concatenation or raw
        # string literals) don't slip past.
        for op, pat in patterns.items():
            for m in pat.finditer(text):
                lineno = offset_to_line(m.start())
                if lineno in cfg_test_lineset:
                    continue
                table = m.group(1).lower()
                snippet = text[m.start():m.end()].replace("\n", " \\n ")
                if len(snippet) > 160:
                    snippet = snippet[:160] + "..."
                if rel in ALLOWED_WRITERS:
                    ok_count += 1
                    print(f"OK: {op} {table} at {rel}:{lineno}")
                else:
                    errors.append(
                        f"ERROR: {op} on projection-tracked table '{table}' at {rel}:{lineno}: {snippet}"
                    )

# Second pass: forbid DSL-level access-control-critical table writes
# through the generic `WriteOp::InsertOrIgnore { ... table: "<table>", ... }`
# pattern.
#
# For key_secrets, the typed variant WriteOp::InsertKeySecret* is the
# sole legitimate construction path.
#
# For peers_shared, writes come from a specific projector file which is
# allow-listed explicitly.
#
# Uses DOTALL so the regex spans newlines: real code puts "WriteOp::InsertOrIgnore {"
# on one line and `table: "<name>",` on a subsequent line. The `[^}]*?`
# non-greedy body match stays within a single struct literal so a later
# WriteOp construction in the same file doesn't spuriously match across
# struct boundaries.
def build_dsl_variants(table_name, constant_refs):
    """Return regexes for BOTH InsertOrIgnore and Delete targeting this table.
    Deletes are banned identically: no production projector should construct a
    Delete on access-control-critical tables outside the allow-list.

    `constant_refs` is a list of identifiers whose values resolve to the
    target table at runtime (e.g. `KEY_SECRETS_TABLE`). The regex matches
    either the string literal OR any of the listed constants — so a bypass
    like `WriteOp::InsertOrIgnore { table: KEY_SECRETS_TABLE, ... }` is
    caught as well as `table: "key_secrets"`.
    """
    # Build alternation group: "table_name" | CONST1 | CONST2 | ...
    # Each const is matched as an identifier with optional path qualifiers
    # (e.g., `key_shared::KEY_SECRETS_TABLE` or just `KEY_SECRETS_TABLE`).
    alternatives = [r'"' + table_name + r'"']
    for c in constant_refs:
        alternatives.append(r'(?:[A-Za-z_][A-Za-z0-9_]*::)*' + re.escape(c))
    table_group = r'(?:' + r'|'.join(alternatives) + r')'
    return [
        re.compile(
            r'WriteOp::InsertOrIgnore\s*\{[^}]*?table\s*:\s*' + table_group,
            re.DOTALL,
        ),
        re.compile(
            r'WriteOp::Delete\s*\{[^}]*?table\s*:\s*' + table_group,
            re.DOTALL,
        ),
    ]

dsl_patterns = {
    "key_secrets": (
        # KEY_SECRETS_TABLE is a constant in key_shared.rs; match it as an
        # alternative so a `table: KEY_SECRETS_TABLE` bypass is caught.
        build_dsl_variants("key_secrets", ["KEY_SECRETS_TABLE"]),
        # Empty allow set: untyped key_secrets DSL ops (insert OR delete) are
        # categorically forbidden; the typed variant is the only construction path.
        set(),
    ),
    "peers_shared": (
        # No known public constant for peers_shared yet; if one is added,
        # extend this list.
        build_dsl_variants("peers_shared", []),
        {
            "src/event_modules/peer_shared/projector.rs",
        },
    ),
}
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
        for table_name, (pats, allowed_writers) in dsl_patterns.items():
            for pat in pats:
                for m in pat.finditer(text):
                    start_line = offset_to_line(m.start())
                    if start_line in cfg_test_range:
                        continue
                    if rel in allowed_writers:
                        continue
                    snippet = text[m.start():m.end()].replace("\n", " \\n ")
                    if len(snippet) > 160:
                        snippet = snippet[:160] + "..."
                    errors.append(
                        f"ERROR: DSL-level {table_name} mutation (InsertOrIgnore or Delete) "
                        f"at {rel}:{start_line}: {snippet}"
                    )

# Third pass: enforce per-variant constructor scope.
#   - InsertKeySecretFromUnwrap: only emitted by unwrap-gated projectors.
#   - InsertKeySecretLocal: only emitted by the local-peer key_secret projector.
# Any other file constructing these variants is a rule violation.
# Two construction routes are checked:
#   (a) The typed method chain: `KeySecretsRow::new(...).to_write_op_*()`.
#   (b) Direct variant construction: `WriteOp::InsertKeySecret*(...)`.
# Both must be restricted to the allow-list; otherwise a rogue module could
# call the tuple variant constructor directly and bypass the method gate.
VARIANT_ALLOW = {
    # Method-chain constructors.
    "to_write_op_from_unwrap": {
        "src/event_modules/key_shared.rs",
        "src/event_modules/key_rotation.rs",
        "src/event_modules/key_history.rs",
    },
    "to_write_op_local": {
        "src/event_modules/key_secret.rs",
    },
    # Direct variant constructors. These are public enum variants so the
    # type system can't hide them; the gate has to.
    "WriteOp::InsertKeySecretFromUnwrap": {
        # The typed method chain lives here and uses direct construction.
        "src/event_modules/key_shared.rs",
        # The apply executor matches on the variant but never constructs.
        # The projector.rs file has it in the enum definition; we skip
        # comment-lines via the `//` check below so the variant declaration
        # doesn't self-flag.
    },
    "WriteOp::InsertKeySecretLocal": {
        "src/event_modules/key_shared.rs",
    },
}
for method, allowed in VARIANT_ALLOW.items():
    # Use DOTALL so `\s*` spans newlines: a call split across lines like
    #   WriteOp::InsertKeySecretFromUnwrap
    #   (todo!())
    # is still matched.
    if method.startswith("WriteOp::"):
        pattern = re.compile(r"\b" + re.escape(method) + r"\s*\(", re.DOTALL)
    else:
        pattern = re.compile(r"\." + re.escape(method) + r"\s*\(", re.DOTALL)
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
            lines = text.splitlines()
            # Byte-offset → line mapping for whole-file scan.
            line_starts = [0]
            running = 0
            for l in text.splitlines(keepends=True):
                running += len(l)
                line_starts.append(running)
            def offset_to_line(off, _ls=line_starts):
                lo, hi = 0, len(_ls) - 1
                while lo < hi:
                    mid = (lo + hi + 1) // 2
                    if _ls[mid] <= off:
                        lo = mid
                    else:
                        hi = mid - 1
                return lo + 1
            # cfg(test) lineset.
            cfg_test_lines = set()
            in_test_block = False
            test_brace_depth = 0
            cfg_test_pending = False
            for lineno, line in enumerate(lines, 1):
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
                    cfg_test_lines.add(lineno)
                    if test_brace_depth <= 0:
                        in_test_block = False
                        test_brace_depth = 0
                    continue
            # Whole-file scan with DOTALL patterns.
            for m in pattern.finditer(text):
                lineno = offset_to_line(m.start())
                if lineno in cfg_test_lines:
                    continue
                # Skip matches inside line comments.
                ls_prev = line_starts[lineno - 1]
                # Check for a `//` earlier on the same line.
                pre_on_line = text[ls_prev:m.start()]
                if "//" in pre_on_line:
                    continue
                # Skip pattern-match arms. Look ahead a small window after
                # the match for ` => ` (which destructuring match arms use);
                # scan the next ~5 lines worth of text (enough to cover
                # multi-line or-patterns in the apply executor).
                ahead_end = min(m.end() + 400, len(text))
                ahead_window = text[m.end():ahead_end]
                if " => " in ahead_window.split("\n", 6)[0:6].__str__():
                    # Check if any of the next ~6 lines has an arrow before
                    # a `;` or block close. Safer than a substring check.
                    pass
                # Simpler: count arrow vs semicolon positions in the ahead
                # window. If arrow appears before any `;`, treat as pattern.
                arrow_pos = ahead_window.find("=>")
                semi_pos = ahead_window.find(";")
                brace_close_pos = ahead_window.find("}")
                # Earliest terminator.
                terminator = min(
                    p for p in [semi_pos, brace_close_pos] if p != -1
                ) if (semi_pos != -1 or brace_close_pos != -1) else len(ahead_window)
                if arrow_pos != -1 and arrow_pos < terminator:
                    continue
                if rel not in allowed:
                    errors.append(
                        f"ERROR: method {method} called in {rel}:{lineno} "
                        f"but only these files may call it: {sorted(allowed)}"
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
