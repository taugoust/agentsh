# Experimental Stage 1 detached supervisor

This is an MVP for daemonless, per-session ownership. It is intentionally experimental.

## Scope

Implemented Stage 1 plus a narrow Stage 2 tool-API slice:

- `agentsh session start --detach --workspace . --workspace-mode shadow --json`
- per-session state under `${XDG_STATE_HOME:-~/.local/state}/agentsh/sessions/<session-id>/`
- `metadata.json`
- `supervisor.sock`
- one session owned by that supervisor
- `agentsh wrap --server unix://$SUPERVISOR_SOCK --session $SESSION_ID -- <cmd>`
- REST-over-Unix trusted-parent-Pi tool endpoints for `exec_bash`, `read_file`, `write_file`, and `edit_file` under `/api/v1/sessions/{id}/tools/*`

Explicitly not implemented in this stage:

- full trusted parent Pi integration / tool override code in pi-agent-extensions
- subagents
- COW/FUSE workspace backend
- credential broker
- transparent network redirect (the supported first tier is proxy-required)
- overlay workspace backend

Strict detached eBPF configuration uses the stopped-child cgroup/helper setup barrier and refuses session startup unless the supervisor's explicit POST preflight returns proven `readiness=ready,status=ready`. The preflight runs disposable helper attach/locked-map/cleanup, namespace jail, exact-proxy, local direct-TCP, UDP/raw-socket, control-path/env/fd, and refusal-barrier probes without public internet. It is eligible for `ready` only in the installed delegated transient-user-service topology with a synchronous approval manager. Direct/home-manager launch and any failed observation remain `degraded`; strict startup refuses them. Host/kernel acceptance is still required before treating this implementation as deployed. See [network-enforcement-runtime.md](network-enforcement-runtime.md).

## Human smoke recipe

Run this outside restricted coding-agent sandboxes. This repository sandbox cannot run the live supervisor/wrap smoke because it blocks process execution needed by the Go toolchain and AgentSH runtime.

```sh
# 1. Build/use an agentsh binary from this branch.
# If using the repo dev shell:
nix develop --command go build -o ./agentsh ./cmd/agentsh

# 2. Start a detached supervisor with a shadow workspace.
./agentsh session start \
  --detach \
  --workspace . \
  --workspace-mode shadow \
  --policy agent-default \
  --json | tee /tmp/agentsh-detached-session.json

# 3. Export SESSION_ID and SUPERVISOR_SOCK.
export SESSION_ID=$(jq -r '.session_id' /tmp/agentsh-detached-session.json)
export SUPERVISOR_SOCK=$(jq -r '.supervisor_sock' /tmp/agentsh-detached-session.json)
echo "SESSION_ID=$SESSION_ID"
echo "SUPERVISOR_SOCK=$SUPERVISOR_SOCK"

# 4. Verify metadata and socket exist.
test -n "$SESSION_ID"
test -S "$SUPERVISOR_SOCK"
jq . "${XDG_STATE_HOME:-$HOME/.local/state}/agentsh/sessions/$SESSION_ID/metadata.json"

# 5. Wrap a simple command through the supervisor socket.
./agentsh wrap --server "unix://$SUPERVISOR_SOCK" --session "$SESSION_ID" -- echo hello-from-wrap

# 5b. Optional Stage 2 REST tool endpoint checks over the Unix socket.
curl --unix-socket "$SUPERVISOR_SOCK" \
  -H 'Content-Type: application/json' \
  -d '{"command":"echo hello-from-tool","actor":{"kind":"parent"}}' \
  "http://unix/api/v1/sessions/$SESSION_ID/tools/exec_bash"

curl --unix-socket "$SUPERVISOR_SOCK" \
  -H 'Content-Type: application/json' \
  -d '{"path":"agentsh-tool-smoke.txt","content":"hello\n","actor":{"kind":"parent"}}' \
  "http://unix/api/v1/sessions/$SESSION_ID/tools/write_file"

curl --unix-socket "$SUPERVISOR_SOCK" \
  -H 'Content-Type: application/json' \
  -d '{"path":"agentsh-tool-smoke.txt"}' \
  "http://unix/api/v1/sessions/$SESSION_ID/tools/read_file"

# 6. Optional approval watch/resolve exercise.
# In terminal A:
./agentsh approvals watch --session "$SESSION_ID" --json
# In terminal B, resolve a pending approval if one appears:
# ./agentsh approvals resolve --session "$SESSION_ID" --decision approve --scope once <approval-id>

# 7. Exercise review commands. Create a change through a wrapped shell command
# or by editing the shadow worktree from metadata, then inspect/apply/discard.
./agentsh diff "$SESSION_ID"
# Choose one:
# ./agentsh accept "$SESSION_ID"
# ./agentsh reject "$SESSION_ID"

# 8. Stop the detached supervisor.
./agentsh session stop "$SESSION_ID"
```

## Global daemon restart survival check

Use a long-running wrapped command and restart the global daemon while it runs:

```sh
./agentsh session start --detach --workspace . --workspace-mode shadow --json | tee /tmp/agentsh-detached-session.json
export SESSION_ID=$(jq -r '.session_id' /tmp/agentsh-detached-session.json)
export SUPERVISOR_SOCK=$(jq -r '.supervisor_sock' /tmp/agentsh-detached-session.json)

./agentsh wrap --server "unix://$SUPERVISOR_SOCK" --session "$SESSION_ID" -- sh -c 'echo started; sleep 30; echo survived' &
WRAP_PID=$!

# Restart/kill the global daemon here using your local service manager.
# The wrapped command should continue because notify handling is owned by the
# per-session supervisor, not the global daemon.
wait "$WRAP_PID"
./agentsh session stop "$SESSION_ID"
```

## Failure modes and messages

The detached supervisor CLI tries to distinguish common stale-state cases:

- stale `metadata.json` with no `supervisor_sock`
- missing `supervisor.sock`
- dead supervisor owner PID on platforms that support PID liveness checks
- unsupported workspace mode (`overlay`, COW/FUSE modes are not Stage 1)
- daemon unavailable and no usable detached supervisors found

Discovery intentionally ignores invalid JSON, missing sockets, and dead owner PIDs so `agentsh session list --json` does not fail because of stale session directories.

## Current test blockers in this sandbox

Do not treat live supervisor/wrap behavior as validated in the coding-agent sandbox.

Observed blockers:

1. Go compiler execution is denied by the sandbox:

   ```text
   go: error obtaining buildID for go tool compile: fork/exec /nix/store/.../go/pkg/tool/linux_arm64/compile: permission denied
   ```

2. Full CLI package tests require generated eBPF assets:

   ```text
   internal/netmonitor/ebpf/program_linux.go:17:12: pattern connect_bpfel.o: no matching files found
   ```

Commands to run outside the sandbox:

```sh
# Offline metadata helper tests added for Stage 1 hardening:
nix develop --command go test ./internal/detached

# CLI/client integration compile checks:
nix develop --command go test ./internal/cli ./internal/client
nix develop --command go test ./...
nix develop --command go build -o ./agentsh ./cmd/agentsh
```

Then run the human smoke recipe above.
