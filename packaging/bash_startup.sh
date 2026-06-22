#!/bin/bash
# Disable builtins that bypass seccomp policy enforcement
enable -n kill      # Signal sending
enable -n ulimit    # Resource limits
enable -n umask     # File permission mask
enable -n builtin   # Force direct builtin bypass
# Keep the `command` builtin enabled. Nix dev-env scripts use `command` for
# normal dispatch (`nix develop --command ...`); external execs are still
# mediated by AgentSH's execve/seccomp policy, while dangerous pure builtins
# above remain disabled.
enable -n enable    # Prevent re-enabling (MUST be last)
