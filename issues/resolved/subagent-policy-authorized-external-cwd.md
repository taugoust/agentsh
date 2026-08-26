# Permit policy-authorized external subagent working directories

## Status

Resolved.

## Problem

Direct supervised sessions can access external repositories when AgentSH file policy explicitly permits them. Subagent startup nevertheless imposed an unconditional workspace-root check, so a parent could read and edit an authorized repository but could not spawn a child there.

This produced:

```text
subagent cwd must be inside the session workspace
```

The restriction was inconsistent with direct-session policy and prevented legitimate multi-repository work.

## Resolution

Commit `7e8d3a83` resolves and canonicalizes the requested directory, then evaluates external directories through the session's inherited read policy before spawning a child. Policy-authorized external directories are allowed for direct sessions; denied paths remain denied.

Shadow and overlay sessions retain strict workspace confinement because external directories would bypass their isolation and Apply/Discard semantics.
