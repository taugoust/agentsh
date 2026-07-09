# Command `Approve for session` scopes exact argv instead of executable

## Status
Open.

## Problem
`Approve for session` for a command currently behaves like “approve this exact invocation for the session”. Repeated prompts still appear for the same tool when argv changes, e.g. repeated `sqlite3` invocations in one Pi/AgentSH session.

This is misleading: when the UI presents a command approval as “for session”, it should be possible to approve that command/executable for the session, not only one argv hash.

## Evidence
Observed in a current session event DB:

`~/.local/state/agentsh/sessions/session-26c6e2b4-e7ef-4aa5-ac9e-8c8da22dc882/events.db`

Many `approval_resolved` events for `sqlite3` were recorded within seconds, all under `approve-unknown-nix-store-executables`, with `scope=session`, but different `scope_label` values because argv differed.

In `internal/approvals/scope.go`, command scopes are currently exact-invocation scopes:

```go
// NewCommandScope builds a canonical command approval scope for an exact
// command invocation. The key is a stable hash of command + argv so session
// approvals do not accidentally widen to different arguments.
```

The key is a hash of `command + argv`, so these are all different session approval scopes:

- `sqlite3 /path/events.db 'select ... limit 10'`
- `sqlite3 /path/events.db 'select ... limit 50'`
- `sqlite3 -readonly /path/events.db ...`

That explains why `Approve for session` does not suppress future prompts for the same executable.

## Required fix
Add broader command approval scopes so `Approve for session` can mean “approve this executable/command for the session”.

Expected behavior:

- approving a command for the session allows subsequent invocations of the same resolved executable during that session, even with different argv;
- exact-invocation approval may still exist as a narrower option, but it must not be the behavior behind a plain “Approve for session” command prompt;
- for Nix-store executable prompts, the natural session scope is the resolved executable path, not the full argv hash.

Possible scope model:

- approve exact invocation once;
- approve exact invocation for session;
- approve executable path for session;
- possibly approve basename/package for session when appropriate.

## Testing requirements
This must be tested properly.

Add tests covering at least:

- first command invocation prompts;
- approving the executable for session;
- second invocation of the same executable with different args does **not** prompt;
- a different executable still prompts;
- exact-invocation approval, if retained, remains narrow;
- Nix-store executable paths are scoped by resolved executable path, not argv.
