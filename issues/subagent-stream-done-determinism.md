# Guarantee deterministic streamed subagent `done` events

## Status
Open.

## Problem
For streamed `spawn_subagent`, callers should receive exactly one terminal `done` event whenever the HTTP connection is still writable. Today terminal emission is tied to the top-level happy/error path and may be skipped or malformed on panics, early validation after headers, response writer errors, or partial runtime failures.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: streaming writes headers before `runSubagentMode`; after that, errors are emitted only by `stream.Emit("done", ...)` at the end of `spawnSubagentTool`.
- `internal/api/subagent_tool.go`: `subagentStreamer.Emit` ignores marshal/write/flush errors and has no closed/failed state.
- `internal/api/subagent_tool.go`: parallel workers emit concurrently through a mutex, but there is no terminal-event guard.

## Proposed direction
Give `subagentStreamer` an explicit terminal guard and error state. Ensure all post-header paths defer a single `done` event with partial results where possible, and surface stream write errors to the runner so tests can assert behavior.

## Rough priority
Medium.
