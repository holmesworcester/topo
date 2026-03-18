#!/usr/bin/env bash
# Kill orphaned topo daemons (reparented to init, i.e. ppid=1).
#
# Safe to run while tests are active: only kills daemons whose parent
# process has exited. Live test daemons have a living parent (the test
# binary) and are never touched.
#
# Usage:
#   scripts/kill_orphan_daemons.sh          # dry-run (list only)
#   scripts/kill_orphan_daemons.sh --kill   # actually kill them

set -euo pipefail

KILL=false
if [[ "${1:-}" == "--kill" ]]; then
    KILL=true
fi

SELF_PID=$$
found=0

while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    [[ "$pid" == "$SELF_PID" ]] && continue

    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ') || continue
    [[ "$ppid" != "1" ]] && continue

    # Extract --db path from cmdline (first match only)
    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null) || continue
    db=$(echo "$cmdline" | grep -oP '(?<=--db )\S+' | head -1 || true)
    age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ') || age="?"

    found=$((found + 1))
    if $KILL; then
        echo "killing pid=$pid age=${age}s db=$db"
        kill "$pid" 2>/dev/null || true
        # Wait briefly for graceful exit, then force
        for _ in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "$pid" 2>/dev/null || true
    else
        echo "orphan  pid=$pid age=${age}s db=$db"
    fi
done < <(pgrep -f "topo.*--db.*start" 2>/dev/null || true)

if [[ $found -eq 0 ]]; then
    echo "no orphaned topo daemons found"
elif ! $KILL; then
    echo ""
    echo "$found orphan(s) found. Run with --kill to remove them."
fi
