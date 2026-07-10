# Move subagent runtime configuration out of ad-hoc environment variables

## Status
Open.

## Problem
Subagent runtime behavior is configured almost entirely through `AGENTSH_SUBAGENT_*` environment variables. This makes runtime capabilities, protocol versions, depth limits, socket URLs, and task delivery modes implicit and hard to validate or document.

## Evidence / files inspected
- `internal/api/subagent_tool.go`: `subagentRuntimeFromEnv` reads command, args, task mode, protocol, max depth, socket URL, and runtime name from environment.
- `internal/api/subagent_tool.go`: `splitCommandArgs` implements local shell-ish parsing for `AGENTSH_SUBAGENT_ARGS`.
- `internal/cli/supervisor_session.go`: detached mode CLI text says subagents are an MVP non-goal, but the API code can still be configured globally through env.
- Existing related issue: `issues/subagent-structured-event-protocol.md`.

## Proposed direction
Define a typed subagent runtime config in AgentSH config/session metadata with schema validation, supported protocol versions, argv as structured array, and capability advertisement. Environment variables can remain as compatibility overrides but should not be the primary contract.

## Rough priority
Medium.
