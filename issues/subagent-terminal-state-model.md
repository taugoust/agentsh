# Normalize AgentSH subagent terminal states

## Status
Open.

## Problem
Subagent results mix exit codes, `StopReason` strings, `Error`, stderr, parsed final text, and top-level HTTP errors. This does not distinguish completed, failed tool, failed model, failed protocol, timed out, user cancelled, parent request cancelled, supervisor shutdown, or child process failure.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: `subagentResult.StopReason` is stringly typed (`completed`, `error`, `timeout`) and success/failure checks are repeated in single/chain/parallel modes.
- `internal/api/subagent_tool.go`: `ctx.Err()` always becomes `StopReason: "timeout"`, even if the request was cancelled for another reason.
- `internal/api/subagent_tool.go`: `resultErrorSummary` derives display text from `Error`, `Stderr`, or `Final` heuristically.

## Proposed direction
Introduce a typed terminal-state enum plus structured details: exit code, signal, cancellation cause, protocol error, last event/tool, stderr preview, and retryability. Use that type for JSON and stream responses.

## Rough priority
High.
