# Subagent working-directory inheritance

## Problem

Parallel and chained subagent requests carry a request-level parent working directory, but AgentSH previously ignored it for each child. Children without an explicit `cwd` fell back to mutable session state, and relative child paths were resolved from that state rather than from the parent Pi working directory.

This could start children in the wrong directory or reject otherwise valid relative paths as outside the session workspace.

## Resolution

AgentSH now copies request items before validation, inherits the request-level `cwd` for children that omit one, and resolves child-relative directories against that parent directory. Absolute child paths remain unchanged and the existing workspace/symlink confinement checks remain authoritative.

Behavioral tests cover inherited, relative, and absolute child paths and verify that request objects are not mutated.
