# Make approval resolution races single-winner

## Status
Open.

## Problem
Approval timeout/cancellation paths can emit a denial resolution even if another resolver won the race just before the timeout branch runs. This can produce misleading audit events and ambiguous user feedback around cancellation versus explicit approval/denial.

## Evidence / files inspected
- `internal/approvals/manager.go`: `RequestApproval` handles `ctx.Done()` and timer by calling `m.Resolve(...)` but ignores its boolean return, then unconditionally emits `approval_resolved` with `context canceled` or `approval timeout`.
- `internal/approvals/manager.go`: `Resolve` deletes `pending[id]` and returns false when the request was already resolved, but timeout/cancel branches do not branch on that result.
- `internal/approvals/detached_bridge.go`: detached bridge can resolve asynchronously while the originating request is also expiring.

## Proposed direction
Make `pending` resolution an explicit single-winner state transition. Timeout/cancel should emit only when they successfully claim the request; losing branches should observe the stored winner. Consider storing terminal resolution state for later consumers instead of only sending over `p.ch`.

## Rough priority
High.
