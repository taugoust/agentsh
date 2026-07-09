# Investigate repeated file-tree and command session approval prompts

## Status
Open.

## Problem
A live subagent session still produced repeated approval prompts that should have been covered by broader approval scopes.

Observed symptoms:

1. A file access prompt appeared for a `.go` path, probably under `.config` but the exact path is uncertain.
2. The operator selected a file-tree approval.
3. A later prompt appeared for a subdirectory under that tree, apparently `telemetry`, even though the prior tree approval should have covered it.
4. The operator approved `gofmt` for the session inside the subagent multiple times, but later `gofmt` invocations still prompted again.
5. The operator also had to repeatedly approve the same resolved `sqlite3` executable for the session while this investigation was trying to query event databases:

   ```text
   Approve this command for session: /nix/store/p3iz4w8ng3azif27cphwr26074bivii1-sqlite-3.51.2-bin/bin/sqlite3
   ```

This is annoying because broad approvals are supposed to reduce repeated prompts in a single workflow.

## Notes / possible explanations

- The file-tree repeated prompt may be related to the now-fixed lack of command-scoped `Approve once` directory/tree containment, but it was observed in a live session and should be verified against current code.
- The `gofmt` and `sqlite3` repeated command prompts may already be fixed by executable-scoped command session approvals (`921b6aa8`), but existing sessions that started before the fix, stale UI state, an installed/runtime `agentsh` that does not include the fix, or command identity differences could still show the old behavior.
- For `gofmt` / `sqlite3`, compare the approval IDs and emitted scope fields. The command path may differ between invocations, e.g. wrapper path vs resolved Nix-store executable, different package output, or remote/subagent runtime path. For the observed `sqlite3` case, the UI displayed the same resolved Nix-store executable path repeatedly, so if this reproduces on a fresh post-`921b6aa8` session it is likely a real command session scope regression rather than identity drift.
- For file-tree prompts, compare `scope_kind`, `scope_key`, `scope_path`, `scope_rule`, `scope_prefix`, `command_id`, and whether the approval was `scope=once` or `scope=session`.

## Desired behavior

- Approving a recursive file-tree scope should suppress covered descendants according to the selected scope lifetime (`once` for the command, `session` for the session).
- Approving `gofmt` or `sqlite3` for the session should suppress subsequent prompts for that command in the same session when the resolved executable identity is the same.
- If a later prompt is correct because the rule, operation, command identity, session, or resolved path differs, the UI/audit trail should make that clear.

## Investigation checklist

- Capture the exact approval events from `events.db` for the repeated `.go` / `telemetry` prompts.
- Capture repeated `gofmt` and `sqlite3` approval events from the same session and compare `scope_key`, `scope_label`, `command`, `argv`, resolved executable path, rule, and session ID.
- Check whether the repeated prompts came from a pre-fix session or a freshly started session on current `agentsh` / current installed wrapper.
- Check parent Pi vs subagent vs detached supervisor routing: the approval may be stored in a different session or command scope than the later request checks.
- Add regression tests if the repeated prompt reproduces on current code.

## Rough priority
High.
