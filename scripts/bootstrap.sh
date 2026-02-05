#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Installing Rust toolchain (rustup) ..."
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to install rustup. Please install curl and rerun." >&2
    exit 1
  fi
  curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

cd "$ROOT_DIR"

echo "Fetching Rust dependencies..."
cargo fetch

echo "Building (debug)..."
cargo build

echo "Done."
