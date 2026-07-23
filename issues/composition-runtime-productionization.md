# Productionize the sandbox-composition runtime lifecycle

## Status

Implementation complete locally; fresh Rose deployment validation remains pending. The release gate now provisions a helper-owned lease runtime automatically and runs the full QShell composition matrix without `/agentsh-composition-scratch` or project-policy authority over AgentSH control paths.

The working Rose session remains an untouched known-good acceptance reference. The candidate overlay content without control-directory rules has SHA-256 `4ce687d6b44e8920b562aa91c8f071415d7b738d5415581cf712c22161ab852d`; it must be committed at the versioned QShell project path `.agentsh/policy-overlays/overlay.yaml` before testing a separate fresh session.

## Goal

Make composition runtime provisioning an AgentSH-owned lifecycle concern. Project policy should opt into a composition dialect and define payload authority; it must not create, authorize, discover, or clean AgentSH's private staging directories.

## First milestone: lease-scoped runtime

- Extend the existing privileged ephemeral helper bootstrap to create a root-owned, sticky, write/execute-only composition root beneath its unguessable lease directory.
- Publish the exact helper-selected path in protected bootstrap metadata.
- Support `sandbox.composition.bubblewrap.scratch_root: auto`, resolving only a validated path from the active helper lease.
- Revalidate the path after helper rebinding and fail closed before command launch if the lease runtime is absent or malformed.
- Prepend a non-overridable internal deny for the entire runtime, reject plans whose bind sources overlap it, and ensure pivot detaches the old root; project policy must not mention the path.
- Add synthetic mount authority directly to the prepared Landlock ruleset; no project file rule may authorize the control path.
- Clone synthetic mount descriptors, then detach mounts and remove every construction name before Landlock enforcement and descriptor publication.
- Reap empty stale runtime roots and let the lease's systemd `RuntimeDirectory` remove the tree at teardown.
- Emit durable provisioning, startup readiness, per-command pool-cleanup, and typed failure evidence.

## Local validation

- Full automatic-runtime QShell VM gate: `/nix/store/a66rrxaj1la7v3360886kwr5v79h2hvi-vm-test-run-agentsh-qshell-composition-release-gate` (implementation tree before these evidence-only issue edits); log `/tmp/agentsh-composition-runtime-release-gate-post-review.log`.
- The gate proves root-owned mode `1733`, malformed-mode startup refusal, durable `composition_runtime_{provisioned,ready,cleanup,failed}` events, six cleaned command pools with unique command IDs, seven normalized plans, zero approval events, control-environment/runtime non-leakage, and systemd lease-tree teardown.
- The complete AgentSH flake passes; log `/tmp/agentsh-composition-runtime-full-flake-check-final.log`.
- The complete downstream `nix-config` flake passes with `--override-input agentsh path:../agentsh`; log `/tmp/agentsh-composition-runtime-downstream-full-check-final-rerun.log`.
- Focused downstream outputs include `/nix/store/c1x62ql21079972r6ann225k0kkaimi9-agentsh-project-overlay-boundaries-check`, `/nix/store/jac982x4vys3picfrnaqkyl8cl9wig16-pi-supervised-git-ssh-proxy-check`, `/nix/store/lp45nsqbsd66p7flvnqxpa8lwsh8h281-pi-ssh-nethelper-lifecycle-check`, and `/nix/store/jb2fs2dh81idjl70wal1k8ba47s95syg-pi-auto-nethelper-state-migration-check`.
- Lifecycle lock ownership uses the actual Bash process, atomic owner-file publication, and bounded unpublished-owner grace. Deterministic forced-publication-race coverage and three repeated Nix rebuilds pass; log `/tmp/agentsh-composition-runtime-lifecycle-publication-race-repeated.log`.
- Generated Rose config `/nix/store/7lskkw4fp0ljha09avcv04043ixwvljw-agentsh-dos-config.yaml` enables Landlock/composition with `scratch_root: auto`; Graph `/nix/store/6ik1j3yv0lc9va0s5vmcxsff9ypwrx5y-agentsh-dos-config.yaml` keeps Landlock/composition disabled.

## Follow-up cleanup

- Commit the control-free overlay in `qshell-project`, deploy the pinned AgentSH/nix-config pair, and validate a second fresh Rose session before retiring the reference session.
- Capture the reference session's exact acceptance output, plan digest, XDG environment, event database, and zero-approval evidence without stopping it.
- Select dormant composition capability independently of exact outer shell spelling.
- Consolidate the live project overlay and release-gate fixture into one source of truth.
- Parameterize QShell/Rose fixture paths.
- Remove acceptance-only command rules after a second fresh-session regression passes.

## Security invariants

- Landlock, source-aware seccomp mediation, and `no_new_privs` remain mandatory.
- Auto-provisioning must not replace the root-owned parent with a same-UID-owned directory.
- Runtime paths come only from helper-selected protected metadata, never arbitrary request or project values.
- Internal staging authority is unavailable to payload processes and cannot authorize bind sources.
- Cleanup must not follow symlinks or traverse unknown/mounted trees.
