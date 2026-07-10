# Propagate AgentSH subagent cancellation reasons

## Status
Open.

## Problem
Timeouts, user cancellation, HTTP request cancellation, and supervisor shutdown can collapse into ambiguous cancellation errors for `spawn_subagent`. Parent integrations cannot reliably tell whether to retry, show a timeout, or report an operator-initiated cancellation.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: `spawnSubagentTool` creates one `context.WithTimeout` for the whole request; `runSingleSubagent` maps any `ctx.Err()` to `StopReason: "timeout"` and `ExitCode: 124`.
- `internal/api/subagent_tool.go`: parallel/chain modes summarize failures from child `StopReason` without preserving the initiating cancellation source.
- `internal/api/command_timeout.go`: normal exec already uses cancel causes for deadline vs cancellation; subagent code does not.

## Proposed direction
Carry a cancellation cause through subagent runtime (`timeout`, `client_cancelled`, `parent_cancelled`, `supervisor_shutdown`, `user_cancelled`). Return it in structured result and stream `done`, and align with the normal command timeout/cancel cause model.

## Rough priority
High.
