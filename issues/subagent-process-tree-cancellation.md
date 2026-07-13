# Kill subagent process trees on cancellation

## Status
Open.

## Problem
Subagents are launched with `exec.CommandContext`, which reliably kills the direct child on context cancellation but does not establish or reap a process group. Child agents/tools can leave grandchildren running after timeout, request cancellation, or supervisor shutdown.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: `runSingleSubagent` uses `exec.CommandContext(ctx, runtime.Command, args...)` with no `SysProcAttr`/process-group setup and no post-cancel group kill.
- `internal/api/exec.go` and `internal/api/exec_stream.go`: normal session exec paths have substantial process-group kill logic (`killProcessGroup`, ptrace cancellation watchers), showing subagents are a separate, lighter path.
- Existing related issues: `issues/subagent-cancellation-reason-propagation.md`, `issues/subagent-terminal-state-model.md`.

## Proposed direction
Run each subagent under a small process supervisor abstraction shared with normal exec: create an owned process group, terminate the group on context cancellation, bound graceful shutdown, reap children, and report whether cancellation was timeout/user/supervisor initiated.

## Rough priority
High.
