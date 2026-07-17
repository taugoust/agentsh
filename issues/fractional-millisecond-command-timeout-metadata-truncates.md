# Keep fractional command deadlines consistent with millisecond metadata

## Status
Open.

## Problem
Positive durations of at least one millisecond may still contain a fractional millisecond, such as `1.9ms`. AgentSH enforces the full `time.Duration` but serializes `requested_ms`, `effective_ms`, and session defaults/maxima with `Duration.Milliseconds()`, which truncates toward zero.

A client deriving its transport deadline from metadata can therefore cancel before the server's actual deadline.

## Evidence / files inspected
- `internal/commandtimeout/timeout.go`: accepts durations at or above `1ms` and serializes with `Milliseconds()`.
- `internal/policy/model.go`: policy validation rejects only positive values below `1ms`.
- Approval-extension metadata uses ceiling conversion, so rounding semantics are inconsistent.

## Desired behavior
Wire and policy duration precision must match public millisecond metadata. Either require integral-millisecond command timeouts or define and consistently apply a non-shortening rounding rule.

## Acceptance criteria
- Request and policy tests cover fractional-millisecond values.
- Reported milliseconds never describe a deadline shorter than the enforced server deadline.
- Session, result, event, SSE, gRPC, and `exec_bash` metadata use identical rounding semantics.

## Rough priority
Low.
