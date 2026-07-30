# Approve every approval request for one command invocation

## Status

In progress.

## Problem

One top-level AgentSH command can trigger many executable, file, and network approval requests. `Approve once` is command-scoped but target-specific, so a compound shell command such as `command1 || command2` can still prompt separately for every executable and resource.

## Desired behavior

- Approval UIs can select an explicit command-wide option such as “Allow all requests for this command invocation”.
- The grant is bound to the exact `(session_id, command_id)` and never applies to another Pi tool call.
- Already-pending and future approval-required requests for that command are resolved automatically.
- Hard policy denials and unsupported operations remain unaffected.
- The command-wide decision is not persisted as a session grant.
- Audit events identify command-wide grant and use.
