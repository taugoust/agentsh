# Reject invalid exec timeouts before waiting for session admission

## Status
Open.

## Problem
REST, SSE, and gRPC exec paths acquire the per-session execution gate before parsing and validating the caller's timeout string. An invalid request submitted behind a multi-hour command therefore retains a connection and goroutine until the active command finishes instead of failing immediately.

Many invalid requests can cheaply amplify queue/resource use while never being eligible to execute.

## Evidence / files inspected
- `internal/api/core.go`: `LockExecContext` precedes `resolveCommandTimeout`.
- `internal/api/exec_stream.go`: timeout validation occurs after `LockExec`.
- `internal/api/grpc.go`: streaming timeout validation occurs after session admission.
- Existing invalid-timeout coverage uses an idle session and does not exercise queueing.

## Desired behavior
Parse and validate caller-owned timeout syntax before queue admission. The policy default/cap and source may still be selected from one coherent policy snapshot after admission.

## Acceptance criteria
- Malformed, zero, negative, and sub-millisecond requests fail immediately while another command holds the session gate.
- Invalid requests do not enter the execution queue or emit command lifecycle events.
- A valid queued request still resolves its effective policy cap from one admitted policy snapshot.

## Rough priority
Medium.
