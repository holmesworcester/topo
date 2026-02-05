#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REQUIRED=(
  "constrained-connection@0.1.0"
  "futures@0.3"
  "async-trait@0.1"
)

if cargo add -h >/dev/null 2>&1; then
  cargo add "${REQUIRED[@]}"
else
  # Fallback: append to [dependencies] if missing.
  python3 - <<'PY'
import re
from pathlib import Path

deps = {
  "constrained-connection": "0.1.0",
  "futures": "0.3",
  "async-trait": "0.1",
}

path = Path("Cargo.toml")
text = path.read_text()

if "[dependencies]" not in text:
    text += "\n[dependencies]\n"

def has_dep(name: str) -> bool:
    pattern = rf"^{re.escape(name)}\\s*="
    return re.search(pattern, text, flags=re.MULTILINE) is not None

lines = text.splitlines()
out = []
in_deps = False
inserted = False
for line in lines:
    out.append(line)
    if line.strip() == "[dependencies]":
        in_deps = True
        continue
    if in_deps and line.startswith("[") and line.strip().startswith("[") and line.strip() != "[dependencies]":
        if not inserted:
            for k, v in deps.items():
                if not has_dep(k):
                    out.insert(len(out)-1, f'{k} = "{v}"')
            inserted = True
        in_deps = False

if not inserted:
    # Either at EOF or no new section; append at end of dependencies.
    # Find last dependency line position.
    idx = None
    for i, line in enumerate(out):
        if line.strip() == "[dependencies]":
            idx = i
    if idx is None:
        out.append("[dependencies]")
        idx = len(out) - 1
    # Append after idx until next section or EOF.
    insert_at = idx + 1
    while insert_at < len(out) and not (out[insert_at].startswith("[") and out[insert_at].strip().startswith("[")):
        insert_at += 1
    for k, v in deps.items():
        if not has_dep(k):
            out.insert(insert_at, f'{k} = "{v}"')
            insert_at += 1

path.write_text("\\n".join(out) + "\\n")
PY
fi

cargo fetch
echo "Dependencies installed."
