# Extract detached sessions behind a native runtime provider

## Status
Resolved.

## Problem

Detached session startup, recovery, identity validation, and exact cleanup are implemented directly in the CLI. Adding an external MicroVM runtime on top of that code would either duplicate lifecycle semantics or add provider-specific branches throughout the existing supervisor path.

The durable detached recovery record also describes only the native supervisor launch. There is no versioned, backend-neutral record binding an operator-selected runtime profile to the exact session, generation, incarnation, endpoint, and cleanup state.

## Scope

- Define a versioned `RuntimeProvider` / `RuntimeInstance` contract.
- Route the existing detached implementation through a native provider without changing its user-visible behavior.
- Add operator-owned named runtime profiles; keep `native` as the only and default provider.
- Store a separate private runtime-provider manifest so older AgentSH versions can continue to ignore it and read the unchanged detached recovery files.
- Reject runtime-provider selection fields on ordinary session-create requests.
- Add deterministic fake-provider coverage for readiness, cancellation, crash recovery, identity mismatch, and exact cleanup.
- Run committed cleanup under a bounded context independent of a cancelled startup/stop request.

MicroVM launch, Nix evaluation, QEMU arguments, guest protocol, workspace staging changes, and default-runtime rollout are out of scope.

## Rough priority
High. This is the native compatibility seam required before adding an external MicroVM provider.
