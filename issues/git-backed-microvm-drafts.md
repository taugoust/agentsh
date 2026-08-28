# Complete Git-backed MicroVM Drafts

## Status

The AgentSH implementation is complete for downstream integration: clean repository input preparation, durable complete artifacts, authenticated protocol-v3 bundle transfer, private volume materialization, quiescent synthetic result sealing, isolated host verification, exact result export, journaled terminal storage deletion, and exact higher-generation volume recovery after stopped compute or monitor loss. The external v2 provider is admitted only with an exact session-bound input artifact. Recovery durably archives each prior monitor generation and preserves the same volume and artifact identities.

Remaining release work crosses into the operator runtime and frontend:

- run a complete packaged QEMU/KVM acceptance through the operator v2 runner;
- make the operator production profile strict-network-ready while retaining an explicitly diagnostic profile for bring-up;
- complete the downstream `pi-auto` Draft UX and compatibility migration in `nix-config`;
- add end-to-end crash injection around the runner-specific boot boundary once the updated operator runner is available.

No deployment is part of this issue.

## Invariants

- The VM never receives the real repository or host `.git` path.
- Input and result bundles, the workspace volume, guest handshake, and monitor generation are bound to the exact session.
- Result sealing permanently closes writer admission before trusted Git captures the tree.
- Host verification requires one synthetic result commit whose sole parent is the recorded baseline.
- Apply and branch publication remain ordinary trusted-host Git operations; AgentSH does not materialize result trees into a host workspace.
- Storage deletion requires exact stopped runtime evidence and an absorbing `applied` or `discarded` intent.
