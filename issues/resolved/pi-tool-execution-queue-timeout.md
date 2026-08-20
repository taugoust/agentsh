# Pi tool execution queue timed out behind valid long-running commands

## Problem

The Pi `exec_bash` endpoint applied an implicit 30-second execution-admission timeout. AgentSH serializes parent-session commands, while Pi may submit independent tool calls concurrently. Consequently, a queued call failed with `E_QUEUE_TIMEOUT` whenever the command ahead of it legitimately ran for more than 30 seconds, even though neither command had exceeded its own runtime timeout.

This made normal long builds and validation commands cause unrelated tool failures.

## Resolution

- Removed the implicit execution-queue deadline. Calls without `queue_timeout_ms` now wait until admission is available or their request context is cancelled.
- Retained explicit `queue_timeout_ms` support for callers that require bounded queueing.
- Removed the arbitrary 30-second maximum for explicit queue deadlines, while preserving duration-overflow validation.
- Marked queue-timeout outcomes retryable because the command was not dispatched and produced no side effects.
- Added behavioral coverage proving default requests wait for and subsequently acquire admission.
