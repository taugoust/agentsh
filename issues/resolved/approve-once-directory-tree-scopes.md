# Support `Approve once` for directory/tree file approval scopes

## Status
Resolved.

## Problem
File approval prompts can offer directory-level scope options such as first-level directory access and recursive directory-tree access, but those broad scopes only behave correctly for `scope=session` approvals.

When the operator wants to approve a single command/tool call for an entire subdirectory tree, there is no effective `Approve once for this directory/tree` behavior. Selecting `Approve once` with a directory/tree target either falls back to exact-file behavior or stores a command-scoped decision that is only checked by exact scope key. Subsequent accesses to sibling files or nested files in the same command can prompt again even though the operator intended to approve that directory/tree for the current command only.

This is too coarse in both directions:

- `Approve once` is too narrow for commands that legitimately need several files under one subdirectory.
- `Approve for session` is too broad when the user only wants to unblock the current command/tool call.

## Evidence / likely code paths

- `internal/api/file_approval_scope.go` builds file approval `scope_options` including:
  - exact file scope;
  - first-level directory scope via `approvals.NewFileDirScope`;
  - recursive tree scope via `approvals.NewFileTreeScope`;
  - sometimes the parent directory tree.
- `internal/approvals/manager.go` stores `ScopeSession` decisions with `SetScoped`, and `CheckScoped` applies `findFileDirScopedDecision` / `findFileTreeScopedDecision` to session-scoped decisions.
- `internal/approvals/manager.go` stores `ScopeOnce` decisions with `SetCommandScoped`, but `CheckScoped` currently checks `m.commandScoped[sessionID][commandID][scope.Key]` by exact key only. It does not apply the file-dir/file-tree containment matching to command-scoped decisions.

Therefore directory/tree containment semantics exist for session approvals, but not for command-scoped/once approvals.

## Desired behavior

A file approval should support all of these distinct choices:

- approve this exact file once for the current command;
- approve this first-level directory once for the current command;
- approve this recursive directory tree once for the current command;
- approve this exact file for the session;
- approve this first-level directory for the session;
- approve this recursive directory tree for the session.

Expected semantics:

- `Approve once` with a `file-dir` or `file-tree` target should apply only to the current command/tool call (`commandID`).
- Within that command, sibling/nested accesses covered by the selected directory/tree should not prompt again.
- Later commands in the same session should still prompt unless the operator selected `Approve for session`.
- Rule-awareness must be preserved: approving a broad outside-workspace read once must not satisfy a more-specific sensitive rule such as `.env` or credential access under the same tree.
- Denials should follow the same once/session scoping semantics as approvals.

## Proposed direction

Extend command-scoped lookup to support the same file directory/tree containment logic already used by session-scoped lookup.

Possible implementation shape:

- Factor command-scoped lookup in `Manager.CheckScoped` so it can search the current command's scoped decisions by:
  1. exact key;
  2. `file-dir` containment when the requested scope is `file`;
  3. `file-tree` containment when the requested scope is `file`.
- Reuse `findFileDirScopedDecision` and `findFileTreeScopedDecision` for command-scoped decisions, or extract a shared helper used by both command and session scopes.
- Ensure `approval_command_scope_used` audit events are emitted when a command-scoped directory/tree decision is consumed.
- Confirm resolution paths preserve explicit target fields (`scope_kind`, `scope_key`, `scope_path`, `scope_prefix`, etc.) for `scope=once`, not only `scope=session`.

## Testing requirements

Add tests covering at least:

- approving a recursive file-tree scope once allows a second nested file access under the same tree in the same command without prompting;
- approving a first-level directory scope once allows sibling direct children but not deeper descendants;
- a later/different command does not inherit the once directory/tree approval;
- `scope=session` directory/tree behavior remains unchanged;
- rule mismatch under the same directory/tree still prompts;
- denied once directory/tree decisions are also command-scoped and do not leak to later commands.

## Rough priority
High.

## Resolution
Resolved by making command-scoped (`scope=once`) file approval lookup apply the same `file-dir` and `file-tree` containment checks that session-scoped lookup already used.

`Approve once` can now target a first-level directory or recursive directory tree for the current command/tool call only. The implementation preserves exact-key matching, rule-aware directory/tree matching, command isolation, denial semantics, and emits `approval_command_scope_used` when a command-scoped directory/tree decision is consumed.

Commits:
- `28e3d176` (`fix(approvals): honor once directory file scopes`) added command-scoped directory/tree containment lookup and regression tests for recursive tree once, first-level directory once, command isolation, rule mismatch, denied decisions, and existing session tree behavior.
