# Detached supervisor Stage 1 contract

This document is the current Stage 1 interface contract for `pi-agent-extensions` and `nix-config` integration. It describes what exists now, not the future NDJSON protocol from `agent-refactor.md`.

## Available CLI commands

```sh
# Start an experimental detached per-session supervisor.
agentsh session start --detach --workspace . --workspace-mode shadow --json

# List sessions. If the global daemon is unavailable, this falls back to
# discovered usable detached supervisor metadata entries.
agentsh session list --json

# Stop a detached supervisor/session.
agentsh session stop <session-id>

# Watch approvals. Current implementation polls, it is not a socket stream.
agentsh approvals watch --session <session-id> --json
agentsh approvals watch --all --json

# Resolve approvals.
agentsh approvals resolve --session <session-id> --decision approve --scope once <approval-id>
agentsh approvals resolve --session <session-id> --decision deny --scope once <approval-id>

# Review shadow workspace changes.
agentsh diff <session-id>
agentsh accept <session-id>
agentsh reject <session-id>

# Run a wrapped command against the detached supervisor socket.
agentsh wrap --server unix://$SUPERVISOR_SOCK --session $SESSION_ID -- <cmd> [args...]
```

## JSON output shapes

### `agentsh session start --detach --json`

The command returns one JSON object. Top-level fields include the detached supervisor metadata plus `session` and `state_dir`.

```json
{
  "session_id": "session-...",
  "id": "session-...",
  "created_at": "2026-06-27T12:13:14.123456789Z",
  "state": "active",
  "policy": "agent-default",
  "real_workspace": "/absolute/real/workspace",
  "workspace_mode": "shadow",
  "worktree": "/.../agentsh/sessions/session-.../workspace/session-.../work",
  "supervisor_sock": "/.../agentsh/sessions/session-.../supervisor.sock",
  "owner_pid": 12345,
  "protocol_version": 1,
  "session": {
    "id": "session-...",
    "state": "ready",
    "created_at": "2026-06-27T12:13:14.123456789Z",
    "workspace": "/absolute/real/workspace",
    "workspace_mount": "/.../workspace/session-.../work",
    "workspace_mode": "shadow",
    "shadow": {
      "enabled": true,
      "state": "active",
      "real": "/absolute/real/workspace",
      "work": "/.../workspace/session-.../work",
      "home": "/.../workspace/session-.../home",
      "tmp": "/.../workspace/session-.../tmp",
      "created_at": "2026-06-27T12:13:14.123456789Z"
    },
    "policy": "agent-default",
    "command_timeout": {
      "default_ms": 900000,
      "maximum_ms": 900000,
      "approval_extension_ms": 300000,
      "source": "policy"
    },
    "cwd": "/workspace",
    "virtual_root": "/workspace",
    "project_root": "/.../workspace/session-.../work",
    "git_root": "/.../workspace/session-.../work"
  },
  "state_dir": "/.../agentsh/sessions/session-..."
}
```

### `metadata.json`

Located at:

```text
${XDG_STATE_HOME:-~/.local/state}/agentsh/sessions/<session-id>/metadata.json
```

Stable shape:

```json
{
  "session_id": "session-...",
  "id": "session-...",
  "created_at": "2026-06-27T12:13:14.123456789Z",
  "state": "active",
  "policy": "agent-default",
  "real_workspace": "/absolute/real/workspace",
  "workspace_mode": "shadow",
  "worktree": "/.../workspace/session-.../work",
  "supervisor_sock": "/.../supervisor.sock",
  "owner_pid": 12345,
  "network_enforcement": {
    "requested": "best-effort",
    "readiness": "degraded",
    "status": "degraded",
    "tier": "none",
    "network_policy_enforced": false,
    "cgroup_delegated": false,
    "helper_authenticated": false,
    "tool_boundary_active": false,
    "proxy_ready": false,
    "direct_bypass_blocked": false,
    "unsupported_traffic_blocked": false,
    "fail_closed_setup": false,
    "transparent_redirect": false,
    "checked_at": "2026-07-10T12:13:14Z",
    "preflight": {
      "status": "degraded",
      "cgroup_placement_proven": false,
      "helper_authenticated": false,
      "helper_attach_proven": false,
      "default_deny_map_proven": false,
      "helper_cleanup_proven": false,
      "proxy_listener_proven": false,
      "tool_boundary_proven": false,
      "direct_bypass_proven": false,
      "unsupported_traffic_proven": false,
      "fail_closed_barrier_proven": false,
      "checked_at": "2026-07-10T12:13:14Z"
    }
  },
  "protocol_version": 1
}
```

The object is runtime evidence, not launch intent. See [network-enforcement-runtime.md](network-enforcement-runtime.md). `network_policy_enforced` is defensively forced to false unless every proxy-required prerequisite is proven.

### `agentsh session list --json` detached fallback entries

When the global daemon is unavailable, `session list --json` returns an array of metadata entries discovered from the detached sessions state dir. Invalid JSON, missing sockets, and dead owner PIDs are ignored.

```json
[
  {
    "session_id": "session-...",
    "id": "session-...",
    "created_at": "2026-06-27T12:13:14.123456789Z",
    "state": "active",
    "policy": "agent-default",
    "real_workspace": "/absolute/real/workspace",
    "workspace_mode": "shadow",
    "worktree": "/.../workspace/session-.../work",
    "supervisor_sock": "/.../supervisor.sock",
    "owner_pid": 12345,
    "protocol_version": 1
  }
]
```

## Supervisor socket/API expectations

Stage 1 supervisor socket is **HTTP JSON over Unix socket**, reusing the existing AgentSH REST API transport. It is **not NDJSON**.

Clients should connect with base URL:

```text
unix:///absolute/path/to/supervisor.sock
```

The Go client already supports this via `client.New("unix:///path/to/supervisor.sock", "")`. CLI usage passes the same URL through `--server`.

Currently useful endpoints include:

```text
GET    /api/v1/sessions
POST   /api/v1/sessions
GET    /api/v1/sessions/{id}
GET    /api/v1/sessions/{id}/network-enforcement
POST   /api/v1/sessions/{id}/network-enforcement/preflight
DELETE /api/v1/sessions/{id}
POST   /api/v1/sessions/{id}/wrap-init
GET    /api/v1/sessions/{id}/overlay/diff
POST   /api/v1/sessions/{id}/overlay/accept
POST   /api/v1/sessions/{id}/overlay/reject
GET    /api/v1/approvals
POST   /api/v1/approvals/{id}
```

The POST endpoint is the detached launcher handshake. It may perform only the checks supported by the running architecture and returns degraded rather than inferring readiness from launch mode. Strict launch accepts only a proven `readiness=ready,status=ready` response.

`pi-agent-extensions` should either:

1. call these REST endpoints over the Unix socket, or
2. shell out to the CLI commands above for Stage 1.

## Experimental Stage 2 trusted-parent-Pi tool endpoints

Stage 2 adds **REST JSON over the same Unix socket** for the trusted parent Pi sandbox extension. This is still not the future NDJSON protocol from `agent-refactor.md`.

Base URL:

```text
unix:///absolute/path/to/supervisor.sock
```

Endpoints:

```text
POST /api/v1/sessions/{id}/tools/exec_bash
POST /api/v1/sessions/{id}/tools/read_file
POST /api/v1/sessions/{id}/tools/write_file
POST /api/v1/sessions/{id}/tools/edit_file
POST /api/v1/sessions/{id}/tools/spawn_subagent
```

Common response shape:

```json
{"ok":true,"result":{}}
{"ok":false,"error":"message"}
```

HTTP status codes are meaningful. Policy denials and denied approvals return 403. Bad path/request shapes return 400. Missing files return 404.

### `exec_bash`

Request:

```json
{
  "command": "nix flake check",
  "cwd": ".",
  "timeout_ms": 120000,
  "stdin": "optional stdin",
  "env": {"KEY": "value"},
  "include_events": "summary",
  "actor": {"kind": "parent", "label": "top-level pi"}
}
```

Response result:

```json
{
  "command_id": "cmd-...",
  "session_id": "session-...",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "...",
  "duration_ms": 1234,
  "stdout_truncated": false,
  "stderr_truncated": false,
  "command_timeout": {
    "requested_ms": 120000,
    "effective_ms": 120000,
    "approval_extension_ms": 300000,
    "source": "explicit_request"
  },
  "exec_response": {"...": "full existing ExecResponse"}
}
```

Implementation notes:

- Runs via the existing session exec path as `bash -lc <command>`.
- The REST endpoint returns buffered stdout/stderr; it does not stream chunks yet.
- Uses the session worktree and existing command policy/precheck machinery.
- Runtime supervision is only as strong as the reported evidence. Strict detached eBPF uses the cgroup/helper setup barrier but startup refuses until all readiness prerequisites are proven; non-strict unsupported features degrade explicitly. Transparent networking and FUSE/overlay remain disabled.
- `actor` is copied into command approval/audit metadata where the existing exec path carries request metadata.
- Runtime approvals share one bounded extension allowance. The first positive extension fixes the maximum deadline at the initial effective deadline plus that allowance (normally `approvals.timeout`); sequential approvals cannot accumulate additional allowances. `command_timeout.approval_extension_ms` reports the bound when approvals are enabled.
- Pi's command transport slack must be greater than `approval_extension_ms` plus a cleanup/response margin. The transport deadline must not expire while AgentSH is killing descendants, persisting terminal state, and returning the response.
- AgentSH-owned child Pi processes receive a supervisor-minted `AGENTSH_CHILD_CAPABILITY`. Their extension sends it only as `X-AgentSH-Child-Capability` on `exec_bash` over the supervisor Unix socket. The credential is bound to the session, subagent ID, exact peer PID, stable process identity where supported, and child lifetime; it is scrubbed from executed command environments.
- Each authenticated child is one serialized execution lane. Different child lanes may overlap up to `sessions.subagents.max_exec_concurrency`. The fail-closed default is `1`. Parent/root requests and unsupported transports remain exclusive. Persistent FUSE, ptrace/ESF, cgroup/network-proxy, and strict eBPF paths currently fall back to exclusive admission because their session-wide or proxy-connection attribution cannot yet identify every overlapping command safely.

### `read_file`

Request:

```json
{
  "path": "src/a.ts",
  "cwd": ".",
  "max_bytes": 1048576,
  "actor": {"kind": "parent"}
}
```

Response result:

```json
{
  "path": "/workspace/src/a.ts",
  "real_path": "/.../workspace/session-.../work/src/a.ts",
  "encoding": "utf-8",
  "content": "file text",
  "size": 9,
  "truncated": false
}
```

If the bytes are not valid UTF-8, `encoding` is `base64` and `content` is base64 text. The default read limit is 1 MiB; the hard cap is 4 MiB.

### `write_file`

Request:

```json
{
  "path": "src/a.ts",
  "content": "new file contents\n",
  "encoding": "utf-8",
  "create_dirs": false,
  "actor": {"kind": "parent"}
}
```

For binary content, set `encoding` to `base64` and put base64 data in `content`.

Response result:

```json
{
  "path": "/workspace/src/a.ts",
  "real_path": "/.../workspace/session-.../work/src/a.ts",
  "bytes_written": 18
}
```

### `edit_file`

Request:

```json
{
  "path": "src/a.ts",
  "oldText": "old exact text",
  "newText": "new exact text",
  "actor": {"kind": "parent"}
}
```

Response result:

```json
{
  "path": "/workspace/src/a.ts",
  "real_path": "/.../workspace/session-.../work/src/a.ts",
  "bytes_written": 123,
  "replacements": 1
}
```

`edit_file` requires `oldText` to occur exactly once. Zero matches and multiple matches return 409.

### Stage 2 file endpoint limitations

The file endpoints are a narrow safe MVP:

- They are native supervisor filesystem operations, not child processes wrapped by seccomp notify.
- They are confined to the session workspace mount/worktree and reject lexical or symlink escapes.
- They call the session file policy engine for `read`/`write` and can create normal approval requests when the effective policy decision is enforced `approve`.
- They currently do not implement soft-delete, redirect, chmod/chown metadata preservation, streaming, directory listing, image special-casing, or Pi's full read truncation/image conventions.
- `write_file` does not create missing parent directories unless `create_dirs` is true.
- `spawn_subagent` is implemented as a generic configured child-agent process runner when `AGENTSH_SUBAGENT_COMMAND` is set. It supports request-level `stream: true` using `application/x-ndjson` events for stdout/stderr and final results; true streaming `watch_approvals` and NDJSON `hello` are still not implemented.

Current approval watching remains CLI polling over the existing HTTP approvals endpoint.

## Auth expectations

The detached supervisor Unix socket is local and file-permission protected. Stage 1 configures the supervisor API with local unauthenticated HTTP over that Unix socket.

Approval resolution over this socket is therefore trusted by local socket access. Do not expose `supervisor.sock` outside the local user/session boundary.

## Known unsupported / partial features

Unsupported or partial by design in the current detached supervisor:

- trusted parent Pi is only partially supported through the experimental REST tool endpoints above
- `agentsh-base` tool overrides
- built-in subagent runtimes (the REST MVP requires an explicit `AGENTSH_SUBAGENT_COMMAND` runtime)
- credential broker
- COW/FUSE workspace backend
- overlay workspace backend for detached supervisor MVP
- installed-host acceptance of the implemented same-UID command-jail isolation for helper credentials/control paths
- production/kernel acceptance of the implemented raw-socket denial and helper crash/reload lifecycle
- transparent networking (the named target tier is proxy-required, not transparent)
- NDJSON supervisor protocol
- NDJSON `spawn_subagent` supervisor operations (REST `spawn_subagent` is available when a generic runtime is configured)

## Integration TODO for `pi-agent-extensions`

Recommended environment variables for integration:

```sh
export AGENTSH_SESSION_ID="$SESSION_ID"
export AGENTSH_SESSION_SUPERVISOR="unix://$SUPERVISOR_SOCK"
```

Start command if no supervisor is already provided:

```sh
agentsh session start --detach --workspace . --workspace-mode shadow --json
```

Current mismatch with sandbox extension mock protocol:

- The mock/planned extension protocol is NDJSON with operations like `hello`, `exec_bash`, `write_file`, and `watch_approvals`.
- Real AgentSH exposes REST endpoints over HTTP on the Unix socket. Stage 2 now includes REST equivalents for `exec_bash`, `read_file`, `write_file`, and `edit_file`.
- `pi-agent-extensions` must call these REST endpoints directly, shell out to CLI for non-tool operations, or keep an adapter layer for any remaining NDJSON expectations.

## Outside-sandbox smoke commands

Do not run these inside restricted coding-agent sandboxes.

```sh
# Build binary.
nix develop --command go build -o ./agentsh ./cmd/agentsh

# Start detached supervisor.
./agentsh session start --detach --workspace . --workspace-mode shadow --policy agent-default --json \
  | tee /tmp/agentsh-detached-session.json

# Export integration variables.
export SESSION_ID=$(jq -r '.session_id' /tmp/agentsh-detached-session.json)
export SUPERVISOR_SOCK=$(jq -r '.supervisor_sock' /tmp/agentsh-detached-session.json)
export AGENTSH_SESSION_ID="$SESSION_ID"
export AGENTSH_SESSION_SUPERVISOR="unix://$SUPERVISOR_SOCK"

# Verify socket and metadata.
test -S "$SUPERVISOR_SOCK"
jq . "${XDG_STATE_HOME:-$HOME/.local/state}/agentsh/sessions/$SESSION_ID/metadata.json"

# Wrap command through supervisor.
./agentsh wrap --server "unix://$SUPERVISOR_SOCK" --session "$SESSION_ID" -- echo hello-from-wrap

# Watch approvals in another terminal if policy creates pending approvals.
./agentsh approvals watch --session "$SESSION_ID" --json

# Resolve approval if one appears.
# ./agentsh approvals resolve --session "$SESSION_ID" --decision approve --scope once <approval-id>

# Review workspace changes.
./agentsh diff "$SESSION_ID"
# Choose one when testing real changes:
# ./agentsh accept "$SESSION_ID"
# ./agentsh reject "$SESSION_ID"

# Stop supervisor.
./agentsh session stop "$SESSION_ID"
```
