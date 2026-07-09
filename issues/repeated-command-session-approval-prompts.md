# Repeated command `Approve for session` prompts for same executable

## Status
Open.

## Problem
A fresh AgentSH/Pi session still produced repeated command approval prompts after the operator selected `Approve for session` for the same resolved executable.

Confirmed reproduction used `sqlite3`: multiple harmless invocations with different argv prompted more than once even after approving the command for the session.

The repeated prompt displayed the same resolved executable path:

```text
/nix/store/p3iz4w8ng3azif27cphwr26074bivii1-sqlite-3.51.2-bin/bin/sqlite3
```

Similar repeated prompts were also observed for `gofmt`, though that still needs a focused reproduction.

## Why this is wrong
Plain command `Approve for session` should store an executable-scoped session approval. Later invocations of the same resolved executable in the same session should use the cached approval even when argv differs.

This should already be covered by commit `921b6aa8` (`fix(approvals): scope command session approvals by executable`), so this issue tracks a remaining regression in propagation, storage, lookup, selected-scope handling, or supervisor/session routing.

## Non-issue explicitly removed
A separate `.config/go` → `.config/go/telemetry` prompt was initially suspected to be related, but that appears to be expected because the first approval was for read access and the later prompt was for write access. File/tree scopes are operation-specific, so that case is not tracked here.

## Areas to inspect

- `internal/api/command_approval.go`
- `internal/api/notify_linux.go`
- `internal/api/command_approval_scope.go`
- `internal/approvals/manager.go`
- `internal/api/app.go` approval resolution paths
- `internal/api/approval_ui.go`
- `internal/api/detached_push.go`
- `internal/approvals/detached_bridge.go`
- `~/Workspace/pi-agent-extensions/sandbox/index.ts` approval option selection / resolution body

## Investigation checklist

- Verify the fresh runtime actually includes `921b6aa8`.
- Capture repeated `sqlite3` approval events and compare:
  - session ID;
  - command ID;
  - approval ID;
  - resolved command path;
  - rule;
  - `scope_kind`;
  - `scope_key`;
  - `scope_label`;
  - whether `approval_scope_granted` is emitted after the first approval;
  - whether the second invocation emits `approval_scope_used` before prompting.
- Check whether Pi sends an exact-invocation scope target despite showing an executable/session approval label.
- Check whether approval is stored in a parent/central supervisor while the later command checks a child/detached supervisor manager.
- Check whether multiple prompts are concurrent stale pending approvals created before the first approval resolution.

## Expected fix

Once root cause is known, add a regression test that proves:

- first `sqlite3` invocation prompts;
- selecting executable `Approve for session` stores a command executable scope;
- later same executable with different argv does not prompt;
- emitted events include `approval_scope_granted` followed by `approval_scope_used`;
- detached/subagent routing, if involved, preserves the scoped decision in the manager that performs later checks.

## Rough priority
High.
