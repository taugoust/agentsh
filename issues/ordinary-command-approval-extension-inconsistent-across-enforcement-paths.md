# Apply ordinary-command approval extensions across every enforcement path

## Status
Open.

## Problem
Ordinary-command metadata advertises one cumulative `approval_extension_ms`, but the extension callback is carried only in the command runner's `context.Context`. Seccomp runtime approvals inherit that context; explicit proxy and FUSE approvals use independent request/operation contexts and therefore cannot extend the command deadline. Pre-command and package approvals also occur before the command timer is installed.

A client can consequently derive a transport deadline from metadata that does not match actual server behavior.

## Evidence / files inspected
- `internal/api/command_timeout.go`: installs the extension callback on the runner context.
- `internal/approvals/timeout_extension.go`: discovers the callback only through context values.
- `internal/netmonitor/proxy.go`: proxy approvals use the proxy request context.
- `internal/fsmonitor/fuse.go`: FUSE approvals use the filesystem operation context.
- `internal/api/core.go`: pre-command/package approvals run before `withExtendableCommandTimeout`.
- `pkg/types/command_timeout.go`: describes `approval_extension_ms` as command-wide.

## Desired behavior
The advertised approval allowance must truthfully cover every approval path attributed to the command, or metadata must explicitly describe a narrower scope. Pre-command and runtime waits must share one bounded command-owned allowance.

## Acceptance criteria
- Deterministic tests cover pre-command, seccomp, proxy, and FUSE approval waits.
- Sequential approval paths cannot exceed the advertised cumulative allowance.
- Session/result metadata and the enforced deadline remain consistent.
- Subagent timeout behavior is unchanged.

## Rough priority
High.
