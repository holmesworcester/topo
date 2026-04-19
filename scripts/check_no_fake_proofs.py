#!/usr/bin/env python3
"""Enforce the no-fake-proofs rule for verus-proofs/.

A "fake proof" is a `spec fn` or `proof fn` that is NOT grounded on runtime
code — i.e., it has no call path from a `pub fn` with `ensures` whose body
is SMT-checked against real runtime behavior. They pass `cargo-verus verify`
but say nothing about the runtime; they are indistinguishable from wishful
thinking.

Rules (enforced in order, flag if a file's spec/proof fns match none):

1. A `spec fn` is grounded if it is cited by an `ensures` clause within the
   same file (directly or transitively), OR in any file under
   `verus-proofs/src/`.
2. A `proof fn` is grounded if it proves a property about a spec that is
   itself grounded.
3. Explicit allow-list: files in EXEMPT_FILES may contain abstract
   spec/proof fns, typically because they document known runtime bugs
   (bug_hunt.rs) or protocol-level frame shapes cited by neighbouring
   grounded ensures (session_auth.rs `*_spec`).

Exit 0 if clean, 1 if fakes detected. Prints a report of offending items.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
VERUS_SRC = REPO_ROOT / "verus-proofs" / "src"

# Files allowed to contain abstract spec/proof fns without runtime grounding.
# Each entry needs a brief justification in the CODEBASE, not just here.
EXEMPT_FILES = {
    # Bug-hunt: proofs of known runtime BUGS (counterexamples), not of
    # correctness. Shrinks as bugs are fixed; each finding flips into a
    # positive invariant once its runtime bug is resolved.
    "bug_hunt.rs",
    # session_auth.rs: three `*_spec` protocol-frame predicates cited by
    # grounded `*_decide` exec fns in the same file. The runtime cross-checks
    # the decide-fn outcome against its own richer auth planner via
    # debug_assert_eq! in src/runtime/transport/session_auth.rs.
    "runtime/transport/session_auth.rs",
    # state/access_control.rs: system-level invariant scaffold. Four
    # `#[verifier::external_body]` projector lemmas (L1..L4) correspond 1:1
    # with TLA invariants already checked by TLC. The top-level composition
    # (`non_invited_cannot_decrypt`) is SMT-proven from these axioms. Each
    # lemma is expected to be discharged against runtime projector code in
    # future PRs (one at a time); when all four are grounded, this entry
    # can be removed.
    "state/access_control.rs",
}

SPEC_FN_PATTERN = re.compile(r"^\s*(pub\s+)?(open|closed)\s+spec\s+fn\s+(\w+)", re.MULTILINE)
PROOF_FN_PATTERN = re.compile(r"^\s*(pub\s+)?proof\s+fn\s+(\w+)", re.MULTILINE)
ENSURES_PATTERN = re.compile(r"\bensures\b", re.MULTILINE)
EXEC_FN_WITH_ENSURES_PATTERN = re.compile(
    r"pub\s+fn\s+\w+\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->[^{]+)?\s*(?:where[^{]+)?\s*\n?\s*(?:requires[^}]*?)?\s*ensures",
    re.DOTALL,
)


def iter_verus_files() -> Iterable[Path]:
    for path in sorted(VERUS_SRC.rglob("*.rs")):
        if path.name == "lib.rs" or path.name == "mod.rs":
            continue
        yield path


def rel(p: Path) -> str:
    return str(p.relative_to(VERUS_SRC))


def file_is_exempt(p: Path) -> bool:
    relpath = rel(p)
    return relpath in EXEMPT_FILES


def find_spec_and_proof_names(text: str) -> tuple[set[str], set[str]]:
    specs = {m.group(3) for m in SPEC_FN_PATTERN.finditer(text)}
    proofs = {m.group(2) for m in PROOF_FN_PATTERN.finditer(text)}
    return specs, proofs


def find_all_names_used_in_ensures(text: str) -> set[str]:
    """Return the set of identifiers that appear anywhere between `ensures`
    and the start of the next fn body (heuristic)."""
    names: set[str] = set()
    # Simple: grab everything between `ensures` and the following `{` that
    # opens a function body. We'll scan conservatively.
    #
    # For each `ensures` occurrence, look ahead to the next unbalanced `{`.
    i = 0
    while True:
        m = ENSURES_PATTERN.search(text, i)
        if not m:
            break
        start = m.end()
        # Find the next '{' at depth 0 that opens the function body.
        depth_angle = 0
        depth_paren = 0
        j = start
        while j < len(text):
            c = text[j]
            if c == "<":
                depth_angle += 1
            elif c == ">":
                depth_angle = max(0, depth_angle - 1)
            elif c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren = max(0, depth_paren - 1)
            elif c == "{" and depth_angle == 0 and depth_paren == 0:
                break
            j += 1
        region = text[start:j]
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", region):
            names.add(name)
        i = j + 1
    return names


def file_has_grounded_exec_fn(text: str) -> bool:
    return bool(EXEC_FN_WITH_ENSURES_PATTERN.search(text))


def main() -> int:
    if not VERUS_SRC.is_dir():
        print(f"FAIL: {VERUS_SRC} not found", file=sys.stderr)
        return 1

    # First pass: collect all ensures-clause citations across every file.
    global_ensures_names: set[str] = set()
    file_texts: dict[Path, str] = {}
    for p in iter_verus_files():
        text = p.read_text()
        file_texts[p] = text
        global_ensures_names |= find_all_names_used_in_ensures(text)

    offenders: list[str] = []

    for p, text in file_texts.items():
        if file_is_exempt(p):
            continue
        specs, proofs = find_spec_and_proof_names(text)
        if not specs and not proofs:
            continue

        has_exec_with_ensures = file_has_grounded_exec_fn(text)

        # A spec fn is grounded if its name appears in any ensures clause
        # anywhere in verus-proofs/src.
        ungrounded_specs = sorted(s for s in specs if s not in global_ensures_names)

        # A proof fn is grounded if:
        #   - it's about a grounded spec (its body references at least one
        #     name in global_ensures_names), OR
        #   - it's in a file that has at least one grounded exec fn (the
        #     proof is framing/auxiliary for that grounded contract), OR
        #   - it has a `_spec`/`finding_` prefix (explicit convention).
        ungrounded_proofs: list[str] = []
        for proof_name in proofs:
            if proof_name == "system_invariants_hold":
                continue  # lib.rs sentinel; ignored by file filter above.
            if has_exec_with_ensures:
                continue
            if proof_name.startswith("finding_"):
                continue
            if proof_name.endswith("_spec"):
                continue
            # Heuristic: does the proof body cite any grounded spec name?
            proof_body_match = re.search(
                rf"proof\s+fn\s+{re.escape(proof_name)}\b[^{{]*\{{(.*?)^}}",
                text,
                re.DOTALL | re.MULTILINE,
            )
            if proof_body_match:
                body = proof_body_match.group(1)
                if any(name in body for name in global_ensures_names):
                    continue
            ungrounded_proofs.append(proof_name)

        if ungrounded_specs or ungrounded_proofs:
            offenders.append(
                f"{rel(p)}:\n"
                f"  ungrounded spec fn: {', '.join(ungrounded_specs) or '(none)'}\n"
                f"  ungrounded proof fn: {', '.join(sorted(ungrounded_proofs)) or '(none)'}"
            )

    if offenders:
        print("FAIL: fake proofs detected in verus-proofs/")
        print()
        for entry in offenders:
            print(entry)
        print()
        print("Each spec/proof fn listed above is not cited by any `ensures`")
        print("clause on a grounded exec fn. Options to fix:")
        print("  1. Ground it: write a matching `pub fn … ensures …` whose")
        print("     body is SMT-checked, and have the runtime call it.")
        print("  2. Delete it: if the runtime doesn't need the property,")
        print("     the proof is documentation at best, noise at worst.")
        print("  3. Add the file to EXEMPT_FILES in this script, with a")
        print("     written justification in the code and here.")
        return 1

    print("PASS: no fake proofs detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
