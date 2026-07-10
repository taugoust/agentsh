# Unify ptrace execve approval UX with seccomp execve approvals

## Status
Open.

## Problem
Command policies with `approve` have different behavior depending on enforcement backend. Seccomp execve can synchronously request approval; ptrace execve denies approval-required nested execs with a rule suffix. This surprises operators and makes policy portability backend-dependent.

## Evidence / files inspected
- `internal/netmonitor/unix/execve_handler.go`: seccomp execve `approve` calls `handlePolicyApproval` and `ApprovalRequester` with timeout handling.
- `internal/api/notify_linux.go`: `approvalRequesterAdapter` adapts `approvals.Manager` for seccomp execve approvals.
- `internal/api/ptrace_handlers.go`: ptrace `HandleExecve` maps `types.DecisionApprove` to deny with rule text `approval required, denied in ptrace mode`.
- `internal/api/command_approval.go`: top-level command precheck has a third approval path, separate from nested execve handling.

## Proposed direction
Either implement a ptrace-safe approval wait path with timeout extension and tracee suspension semantics, or validate/warn at session start that nested exec approvals are unsupported in ptrace mode. UI/audit should clearly distinguish top-level command approval from nested execve approval.

## Rough priority
High.
