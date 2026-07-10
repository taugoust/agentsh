# Finish or gate ptrace redirect exec stub IPC

## Status
Open.

## Problem
Ptrace exec redirect contains a partial socketpair/fd-injection path but explicitly closes the tracer side immediately because stub IPC is not implemented. Redirect policy behavior can therefore differ sharply between seccomp redirect and ptrace redirect, and future work may assume the channel exists when it does not.

## Evidence / files inspected
- `internal/ptrace/redirect_exec.go`: `redirectExec` creates a socketpair, injects fd 100, then has a TODO saying `tracerFD` should be kept alive until stub handshake/IPC is complete; it is currently closed immediately.
- `internal/netmonitor/unix/handler.go`: seccomp redirect path calls `handleRedirect`, modifies execve to the stub, and comments about stub communication.
- `internal/api/ptrace_handlers.go`: ptrace `DecisionRedirect` returns `Action: "redirect"` and `StubPath` without surfacing the incomplete IPC limitation.

## Proposed direction
Either complete a shared redirect/stub protocol for ptrace and seccomp or gate ptrace redirect as unsupported with explicit policy validation and audit messages. Add integration tests proving redirected commands can exchange I/O and preserve exit status under ptrace.

## Rough priority
Medium.
