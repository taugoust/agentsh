# Repeated command `Approve for session` prompts for same executable

## Status
Resolved.

## Problem
A fresh AgentSH/Pi session still produced repeated command approval prompts after the operator selected `Approve for session` for the same resolved executable.

Confirmed reproduction used `sqlite3`: multiple harmless invocations with different argv prompted more than once even after approving the command for the session.

The repeated prompt displayed the same resolved executable path:

```text
/nix/store/p3iz4w8ng3azif27cphwr26074bivii1-sqlite-3.51.2-bin/bin/sqlite3
```

Similar repeated prompts were also observed for `gofmt`, though that still needs a focused reproduction.

## Root cause
Session-scoped command approvals were cached correctly for later checks, but concurrent approval requests that were already pending before the first approval resolution were left in the pending queue.

Pi prompts pending approvals serially, so after approving one `sqlite3` request for the session, Pi could immediately show the next already-pending `sqlite3` request. That looked like the session approval was ignored even though subsequent newly-created checks would use the cached executable scope.

The detached pushed-approval store had the same pending-queue behavior.

## Resolution
Fixed by `4ba4c1e2` (`fix(approvals): resolve pending covered session prompts`).

The fix resolves/removes other pending approvals in the same session when a new session-scoped approval covers them, including detached pushed approvals. Regression coverage was added for:

- manager-level concurrent command approvals covered by executable session scope;
- exact invocation scopes remaining narrow;
- local REST approval resolution with Pi-selected executable session scope;
- legacy approval UI resolution with Pi-selected executable session scope;
- detached pushed approvals covered by executable session scope.

A dedicated Nix flake check, `approval-regression-tests`, now runs these approval regressions.

Validation:

```sh
nix build .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).approval-regression-tests --no-link
nix build .#checks.$(nix eval --raw --impure --expr builtins.currentSystem).go-unit-tests --no-link
nix build .#default --no-link
nix flake check
```

## Non-issue explicitly removed
A separate `.config/go` → `.config/go/telemetry` prompt was initially suspected to be related, but that appears to be expected because the first approval was for read access and the later prompt was for write access. File/tree scopes are operation-specific, so that case is not tracked here.
