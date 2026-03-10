#!/usr/bin/env bash
set -euo pipefail

count="${1:-50000}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

TOPO="$(pwd)/target/release/topo"
cargo +stable build --release --bin topo >/dev/null

run_dir="$(mktemp -d)"
alice_db="$run_dir/alice.db"
bob_db="$run_dir/bob.db"

cleanup() {
  "$TOPO" --db "$alice_db" stop >/dev/null 2>&1 || true
  "$TOPO" --db "$bob_db" stop >/dev/null 2>&1 || true
  rm -rf "$run_dir"
}
trap cleanup EXIT

socket_path_for_db() {
  local db="$1"
  local dir base
  dir="$(dirname "$db")"
  base="$(basename "$db")"
  base="${base%.*}"
  printf '%s/%s.topo.sock\n' "$dir" "$base"
}

wait_for_ready() {
  local db="$1"
  local require_active="${2:-0}"
  local socket
  socket="$(socket_path_for_db "$db")"
  for _ in $(seq 1 200); do
    if [ -S "$socket" ] && "$TOPO" --db "$db" status >/dev/null 2>&1; then
      if [ "$require_active" = "0" ] || "$TOPO" --db "$db" active-tenant >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.1
  done
  echo "daemon did not become ready for $db" >&2
  return 1
}

stop_if_running() {
  local db="$1"
  "$TOPO" --db "$db" stop >/dev/null 2>&1 || true
}

start_daemon() {
  local db="$1"
  "$TOPO" --db "$db" start --bind 127.0.0.1:0 >/dev/null 2>&1 &
}

setup_alice() {
  if start_daemon "$alice_db" && wait_for_ready "$alice_db"; then
    if "$TOPO" create-workspace --db "$alice_db" --workspace-name ws --username alice --device-name alice >/dev/null 2>&1; then
      wait_for_ready "$alice_db" 1
      return 0
    fi
  fi

  stop_if_running "$alice_db"
  rm -f "$(socket_path_for_db "$alice_db")"
  "$TOPO" create-workspace --db "$alice_db" --workspace-name ws --username alice --device-name alice >/dev/null
  start_daemon "$alice_db"
  wait_for_ready "$alice_db" 1
}

setup_bob() {
  local invite_link="$1"
  if start_daemon "$bob_db" && wait_for_ready "$bob_db"; then
    if "$TOPO" accept --db "$bob_db" "$invite_link" --username bob --devicename bob >/dev/null 2>&1; then
      wait_for_ready "$bob_db" 1
      return 0
    fi
  fi

  stop_if_running "$bob_db"
  rm -f "$(socket_path_for_db "$bob_db")"
  "$TOPO" accept --db "$bob_db" "$invite_link" --username bob --devicename bob >/dev/null
  start_daemon "$bob_db"
  wait_for_ready "$bob_db" 1
}

setup_alice
invite_link="$(
  "$TOPO" --db "$alice_db" invite \
    --public-addr "$("$TOPO" --db "$alice_db" status | awk '/Listen:/ {print $2; exit}')" |
    awk '/^topo:\/\// {print; exit}'
)"
setup_bob "$invite_link"

"$TOPO" --db "$alice_db" send warmup >/dev/null
for _ in $(seq 1 100); do
  bob_count="$(sqlite3 "$bob_db" 'select count(*) from messages;')"
  if [ "$bob_count" = "1" ]; then
    break
  fi
  sleep 0.1
done

if [ "$(sqlite3 "$bob_db" 'select count(*) from messages;')" != "1" ]; then
  echo "warmup did not sync" >&2
  exit 125
fi

"$TOPO" --db "$alice_db" generate --count "$count" >/dev/null
for _ in $(seq 1 120); do
  bob_count="$(sqlite3 "$bob_db" 'select count(*) from messages;')"
  if [ "$bob_count" = "$((1 + count))" ]; then
    echo "PASS count=$count bob_count=$bob_count"
    exit 0
  fi
  sleep 0.5
done

alice_count="$(sqlite3 "$alice_db" 'select count(*) from messages;')"
bob_count="$(sqlite3 "$bob_db" 'select count(*) from messages;')"
echo "FAIL count=$count alice_count=$alice_count bob_count=$bob_count" >&2
exit 1
