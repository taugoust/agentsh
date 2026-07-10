# Deduplicate regular and streaming exec runners

## Status
Open.

## Problem
Regular exec and streaming exec have near-duplicate command runner implementations. The duplicated ptrace, hybrid wrapper, process-group kill, timeout, resource, and pipe-drain logic raises the chance of subtle divergence when fixing cancellation or enforcement bugs.

## Evidence / files inspected
- `internal/api/exec.go`: `runCommandWithResources` is a large runner with ptrace/hybrid/seccomp/cgroup/process cleanup logic.
- `internal/api/exec_stream.go`: `runCommandWithResourcesStreamingEmit` repeats the same control flow with SSE emission changes.
- `wc -l`: `exec.go` is ~937 lines and `exec_stream.go` is ~665 lines.
- `rg` showed mirrored blocks for `CommandContext`, `ptraceSync`, context cancellation watchers, `killProcessGroup`, `commandTimedOut`, and wrapper handlers in both files.

## Proposed direction
Extract one exec runner with pluggable output sinks/events: buffered sink for JSON exec, streaming sink for SSE, shared process lifecycle state machine for ptrace/hybrid/non-ptrace, and shared timeout/cancellation classification.

## Rough priority
High.
