# Make shadow workspace review/accept atomic and quiescent

## Status
Resolved.

## Problem
Shadow workspace accept/reject can race with active commands and is tied to the request context. `Accept` immediately `rsync --delete`s from shadow to real workspace without a reviewed diff generation or command quiescence, so the user may accept different content than they reviewed.

## Evidence / files inspected
- `internal/workspace/shadow/shadow_linux.go`: `Diff` and `Accept` each run fresh external commands; `Accept` uses `rsync -a --delete` then removes the shadow dir and marks state accepted.
- `internal/api/overlay.go`: `diffOverlay`, `acceptOverlay`, and `rejectOverlay` call shadow/overlay methods directly from HTTP handlers using `r.Context()`.
- `internal/session/manager.go`: `MarkShadowAccepted` switches `WorkspaceMount` back to the real workspace, but review endpoints do not acquire the session exec lock or stop active writers.

## Proposed direction
Add a review transaction: lock/quiesce session execution, compute and persist a diff generation/hash, accept only a named generation, run accept in a bounded background context, and record accepted file set/hash in audit. Consider rejecting/pausing new execs during review finalization.

## Rough priority
High.

## Resolution
Implemented quiescent workspace-writer admission, content-addressed real/shadow review generations, mandatory fresh accept preconditions, independent bounded finalization, enriched audit events, and focused Nix coverage. Implemented across `e77dda67`, `f8da1575`, `7c8e2304`, `c1349b35`, and `aff8221b`.
