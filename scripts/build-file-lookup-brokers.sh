#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$root/cmd/agentsh-file-lookup-broker/main.c"

build_one() {
  local arch="$1"
  local compiler="$2"
  local required="${3:-false}"
  local out_dir="$root/build/filelookup/linux_${arch}"
  if ! command -v "$compiler" >/dev/null 2>&1; then
    if [ "$required" = true ]; then
      echo "file lookup broker compiler unavailable for ${arch}: ${compiler}" >&2
      return 1
    fi
    echo "skipping optional file lookup broker for ${arch}: ${compiler} unavailable" >&2
    return 0
  fi
  mkdir -p "$out_dir"
  "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -static \
    "$source_file" -o "$out_dir/agentsh-file-lookup-broker"
  if readelf -l "$out_dir/agentsh-file-lookup-broker" | grep -q 'Requesting program interpreter'; then
    echo "file lookup broker for ${arch} is dynamically linked" >&2
    exit 1
  fi
}

build_one amd64 "${CC_AMD64:-gcc}" true
build_one arm64 "${CC_ARM64:-aarch64-linux-gnu-gcc}" false
