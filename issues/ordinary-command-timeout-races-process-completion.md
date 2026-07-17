# Make ordinary-command completion and timeout expiry single-winner

## Status
Open.

## Problem
Approval extension and timer expiry are serialized, but process completion is not. Completion currently stops the timer through deferred cancellation without atomically deciding whether the process completed before the effective deadline.

This permits two race directions:

- a process can finish after the deadline while a delayed timer callback has not yet recorded timeout, and be reported as a natural exit;
- a process can finish before the deadline, cross it during post-exit cleanup, and have its natural result rewritten to exit `124`.

## Evidence / files inspected
- `internal/api/command_timeout.go`: timer expiry is mutex-protected, while `cancelContext` does not establish a completion winner.
- `internal/api/exec.go`: timeout classification occurs in deferred runner logic after process wait and cleanup.
- `internal/api/exec_stream.go`: duplicates the same lifecycle pattern for streaming execution.

## Desired behavior
Process completion and command-timeout expiry must be one atomic terminal-state transition based on the effective deadline. Cleanup and persistence after a winning completion must not change its classification.

## Acceptance criteria
- Synchronization-controlled tests cover completion immediately before and after the deadline.
- A late timer callback cannot turn a completed command into timeout.
- A command completing after the deadline cannot escape timeout because the callback was delayed.
- Timeout still returns code `124` and kills the process tree.

## Rough priority
High.
