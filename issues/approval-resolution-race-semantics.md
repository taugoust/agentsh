# Make approval resolution races single-winner

## Status
Implemented on `fix/approval-resolution-race`; awaiting integration.

## Implementation

AgentSH commit `914c9a4b` gives every pending approval an immutable terminal state selected exactly once under the manager lock. Explicit decisions, cancellation, timeout, and session-scope coverage now share that transition; losing resolvers cannot replace the winner or emit contradictory results. Duplicate pending IDs are rejected rather than replacing another request.

Deterministic manager-level tests cover both race orderings, event truth, scoped decisions, duplicate IDs, session coverage, and cleanup. The focused approval Nix check, Go formatting check, and AgentSH package build pass on aarch64-linux.

Keep this issue open until the feature branch is integrated. Move it to `issues/resolved/` after the merged commit is known.

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
