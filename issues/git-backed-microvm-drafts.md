# Complete Git-backed MicroVM Drafts

## Status

AgentSH now has the one-generation Git Draft data path: clean repository input preparation, durable complete artifacts, authenticated protocol-v3 bundle transfer, private volume materialization, quiescent synthetic result sealing, isolated host verification, exact result export, and journaled terminal storage deletion. The external v2 provider is admitted only with an exact session-bound input artifact.

Remaining before this issue is resolved:

- recover or resume the exact private volume under a new provider generation after intentional pause or monitor loss;
- add deterministic crash coverage around generation rollover and every sealing/finalization phase;
- run a complete packaged QEMU/KVM acceptance through the operator v2 runner;
- require a strict network-ready profile for production admission while retaining explicitly diagnostic profiles for bring-up;
- complete the downstream `pi-auto` Draft UX and compatibility migration in `nix-config`.

No deployment is part of this issue.

## Invariants

- The VM never receives the real repository or host `.git` path.
- Input and result bundles, the workspace volume, guest handshake, and monitor generation are bound to the exact session.
- Result sealing permanently closes writer admission before trusted Git captures the tree.
- Host verification requires one synthetic result commit whose sole parent is the recorded baseline.
- Apply and branch publication remain ordinary trusted-host Git operations; AgentSH does not materialize result trees into a host workspace.
- Storage deletion requires exact stopped runtime evidence and an absorbing `applied` or `discarded` intent.
