# Preserve resolved timeout metadata on execution refusals

## Status
Resolved.

## Problem
Several execution paths resolve the ordinary-command timeout and then refuse execution during strict network-readiness or wrapper setup. Their responses do not carry the resolved metadata consistently.

Buffered responses can serialize a zero-valued `command_timeout` (`effective_ms: 0`, empty source), while HTTP/gRPC streaming refusals can omit it entirely. Trusted Pi clients cannot distinguish these values from malformed or stale supervisor metadata.

## Evidence / files inspected
- `internal/api/core.go`: strict nethelper and wrapper setup refusals occur after timeout resolution.
- `internal/api/exec_stream.go`: post-resolution setup failures return before the normal start/done timeout payloads.
- `internal/api/grpc.go`: streaming setup failures return status errors without resolved timeout details.
- `internal/api/pi_tools.go`: promotes the buffered result's timeout metadata to `exec_bash`.
- `pkg/types/exec.go`: zero-valued timeout metadata is not omitted.

## Desired behavior
Every terminal response after successful timeout resolution must include that exact resolved timeout/source, even when execution is refused before process start. Queue/admission failures where no policy snapshot exists should remain explicitly distinct.

## Acceptance criteria
- Buffered REST, `exec_bash`, SSE, and gRPC refusal fixtures report identical resolved metadata.
- No post-resolution response emits zero/empty timeout metadata.
- Refusal remains distinguishable from command timeout and caller cancellation.

## Rough priority
Medium.

## Resolution
Resolved by AgentSH `6a9f0e42` (`fix(timeout): preserve metadata on refusals`). Strict network-readiness and command-boundary setup refusals now carry the exact timeout metadata resolved after admission. Buffered REST and unary gRPC inherit it from the core result, `exec_bash` preserves both promoted and nested metadata, SSE setup responses include it, and gRPC streams emit a typed `refused` payload before the terminal status. Pre-resolution queue/admission failures remain distinct, and refusal outcomes remain separate from command timeout and caller cancellation. Focused tests verify identical metadata across transports and strict-readiness refusal behavior.
