#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/ephemeral-nethelper-smoke.sh [AGENTSH-BINARY-OR-PACKAGE]

Builds the current AgentSH flake when no argument is supplied, starts one
lease-scoped root nethelper through sudo, validates its runtime state, releases
it without sudo, and verifies cleanup.

Run this from a normal trusted shell, not from inside an AgentSH/Pi tool command.
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

if [ "$(uname -s)" != Linux ]; then
  echo "ephemeral nethelper smoke requires Linux" >&2
  exit 1
fi

if awk '$1 == "NoNewPrivs:" { exit ($2 == 0 ? 1 : 0) } END { if (NR == 0) exit 1 }' /proc/self/status; then
  cat >&2 <<'EOF'
This shell has no_new_privs enabled, so sudo cannot elevate.
Run this script from a separate normal SSH/login shell outside AgentSH.
EOF
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input="${1:-}"
if [ -z "$input" ]; then
  package="$(cd "$repo_root" && nix build .#agentsh --no-link --print-out-paths | tail -n 1)"
  agentsh_bin="$package/bin/agentsh"
elif [ -d "$input" ]; then
  agentsh_bin="$input/bin/agentsh"
else
  agentsh_bin="$input"
fi
agentsh_bin="$(realpath "$agentsh_bin")"

if [ ! -x "$agentsh_bin" ]; then
  echo "agentsh executable not found: $agentsh_bin" >&2
  exit 1
fi
case "$agentsh_bin" in
  /nix/store/*/bin/agentsh) ;;
  *)
    echo "bootstrap requires the immutable Nix package launcher, got: $agentsh_bin" >&2
    exit 1
    ;;
esac

uid="$(id -u)"
gid="$(id -g)"
if [ "$uid" -eq 0 ]; then
  echo "run this smoke as the target non-root user, not root" >&2
  exit 1
fi
lease="$($agentsh_bin nethelper lease-id)"
lease_suffix="${lease#lease-}"
runtime="/run/agentsh/nethelper/$uid/$lease"
socket="$runtime/nethelper.sock"
credential_file="$runtime/instance-credential"
result_file="$runtime/bootstrap.json"
pin_root="/sys/fs/bpf/agentsh/nethelper-ephemeral/$uid/$lease/pins"
unit="agentsh-nethelper-ephemeral-$uid-$lease_suffix.service"
released=0
session_id=""

cleanup() {
  if [ -n "$session_id" ]; then
    "$agentsh_bin" session stop "$session_id" >/dev/null 2>&1 || true
    session_id=""
  fi
  if [ "$released" -eq 0 ] && [ -S "$socket" ] && [ -r "$credential_file" ]; then
    "$agentsh_bin" nethelper release \
      --socket "$socket" \
      --credential-file "$credential_file" \
      --lease "$lease" \
      >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

printf 'agentsh: %s\n' "$agentsh_bin"
printf 'lease:   %s\n' "$lease"
printf 'unit:    %s\n' "$unit"
printf '\nStarting temporary helper (sudo may prompt once)...\n'
sudo "$agentsh_bin" nethelper bootstrap \
  --uid "$uid" \
  --gid "$gid" \
  --lease "$lease"

[ -f "$result_file" ] || { echo "missing bootstrap result: $result_file" >&2; exit 1; }
[ -S "$socket" ] || { echo "missing helper socket: $socket" >&2; exit 1; }
[ -r "$credential_file" ] || { echo "credential copy is not readable by uid $uid" >&2; exit 1; }
[ "$(stat -c '%a' "$socket")" = 600 ] || { echo "helper socket is not mode 0600" >&2; exit 1; }
[ "$(stat -c '%u' "$socket")" = "$uid" ] || { echo "helper socket has wrong owner" >&2; exit 1; }
[ "$(stat -c '%a' "$credential_file")" = 400 ] || { echo "credential copy is not mode 0400" >&2; exit 1; }
[ "$(stat -c '%u' "$credential_file")" = "$uid" ] || { echo "credential copy has wrong owner" >&2; exit 1; }
systemctl is-active --quiet "$unit" || { systemctl status --no-pager "$unit" >&2 || true; exit 1; }

printf '\nBootstrap metadata (contains paths/IDs, never the credential):\n'
cat "$result_file"

jq_bin="$(command -v jq 2>/dev/null || true)"
if [ -z "$jq_bin" ]; then
  jq_package="$(nix build nixpkgs#jq --no-link --print-out-paths | tail -n 1)"
  jq_bin="$jq_package/bin/jq"
fi
[ -x "$jq_bin" ] || { echo "could not obtain jq for evidence validation" >&2; exit 1; }
printf '\nStarting a delegated strict session and disposable preflight...\n'
session_json="$({
  AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN=1 \
  AGENTSH_NETHELPER_SOCKET="$socket" \
  AGENTSH_NETHELPER_CREDENTIAL_FILE="$credential_file" \
  "$agentsh_bin" session start \
    --detach \
    --policy pi-supervised \
    --workspace "$repo_root" \
    --workspace-mode direct \
    --runtime-home real \
    --json
})"
printf '%s\n' "$session_json"
session_id="$(printf '%s\n' "$session_json" | "$jq_bin" -r '.session_id // .id // empty')"
[ -n "$session_id" ] || { echo "strict session output has no session id" >&2; exit 1; }
metadata="${XDG_STATE_HOME:-$HOME/.local/state}/agentsh/sessions/$session_id/metadata.json"
[ -r "$metadata" ] || { echo "strict session metadata is missing: $metadata" >&2; exit 1; }
if ! "$jq_bin" -e '
  .network_enforcement.requested == "strict" and
  .network_enforcement.readiness == "ready" and
  .network_enforcement.status == "ready" and
  .network_enforcement.tier == "helper-ebpf-proxy-required" and
  .network_enforcement.network_policy_enforced == true and
  .network_enforcement.preflight.helper_attach_proven == true and
  .network_enforcement.preflight.default_deny_map_proven == true and
  .network_enforcement.preflight.tool_boundary_proven == true and
  .network_enforcement.preflight.direct_bypass_proven == true and
  .network_enforcement.preflight.udp_blocked == true and
  .network_enforcement.preflight.raw_sockets_blocked == true and
  .network_enforcement.preflight.fail_closed_barrier_proven == true and
  .network_enforcement.preflight.helper_cleanup_proven == true
' "$metadata" >/dev/null; then
  echo "strict session did not report complete live enforcement evidence" >&2
  "$jq_bin" '.network_enforcement' "$metadata" >&2 || true
  exit 1
fi
printf 'strict preflight: ready (%s)\n' "$session_id"
"$agentsh_bin" session stop "$session_id" >/dev/null
session_id=""

printf '\nReleasing temporary helper without sudo...\n'
"$agentsh_bin" nethelper release \
  --socket "$socket" \
  --credential-file "$credential_file" \
  --lease "$lease"
released=1

for _ in $(seq 1 50); do
  if [ ! -e "$runtime" ] && ! systemctl is-active --quiet "$unit"; then
    break
  fi
  sleep 0.1
done

if [ -e "$runtime" ]; then
  echo "temporary helper runtime was not removed: $runtime" >&2
  exit 1
fi
if systemctl is-active --quiet "$unit"; then
  echo "temporary helper unit is still active: $unit" >&2
  exit 1
fi
if sudo -n test -e "$pin_root"; then
  echo "temporary helper pin root was not removed: $pin_root" >&2
  exit 1
fi

trap - EXIT HUP INT TERM
printf '\nephemeral helper lifecycle: OK\n'
