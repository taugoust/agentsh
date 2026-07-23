# Plan: finish the real QShell Bubblewrap composition rollout

## Parent issue

`issues/qshell-bubblewrap-composition-live-rollout-gaps.md`

Downstream architecture/contract plans:

- `nix-config/issues/plans/agentsh-bubblewrap-0112-qshell-contract.md`
- `nix-config/issues/plans/agentsh-composable-nested-bubblewrap.md`

## Status

Open for Phase 6 only. Rose is deployed at AgentSH `68786983` through `nix-config` `93e5383`. Its first harmless Ultrascale canary selected composition but failed closed because Nixpkgs' in-boundary `for dir in /*` scan was denied, yielding a `51`-operation plan without `/scratch` and `E_COMPOSITION_CWD_UNRESOLVED`.

AgentSH remediation `83944d4309d12a0041f2863e4f55ee8046b771a4` adds exact directory-list Landlock authority and a generation-aware release gate. All 15 AgentSH checks and the strengthened downstream gate pass. The candidate and reviewed overlay still must be pushed, pinned, deployed, and exercised on Rose in the exact harmless-first order below. Do not describe live acceptance as complete.

## Constraints

1. Keep mandatory Landlock and `no_new_privs` on the adapter and every payload.
2. Preserve source-aware file, metadata, and exec policy across aliases.
3. Never grant broad write access to `/nix`, `/nix/store`, or `/scratch` to make a bind pass.
4. Keep raw mount APIs, external `setns`, network/time namespaces, and unsupported Bubblewrap options denied.
5. Require both the Rose-only host ceiling and trusted project-overlay selection.
6. Keep all non-Rose hosts disabled.
7. Run builds/tests through Nix flake outputs.
8. Preserve unrelated dirty/untracked files.
9. No hardware programming, reset, `hw_server`, driver, fleet, KVM, or microVM operations.

## Baseline

- semantic implementation: `585d7e61`
- post-start PID and packaged-wrapper identity: `91a8e51d`
- root-level read-only bind reduction: `b1479a2f`
- AgentSH handoff issue: `dca52846`
- latest downstream lock: `nix-config` `5bd4bf3`
- downstream handoff issue: `nix-config` `98b2318`

Known live errors, in order:

```text
bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied
E_COMPOSITION_REQUESTER_CHANGED: trusted wrapper PID is invalid
E_COMPOSITION_RIGHTS_ESCALATION: read-write bind source "/nix" is not base-policy writable
agentsh-bwrap-adapter: chdir /scratch/theo/qshell-project/qshell: ... no such file or directory
```

The first error also remains reproducible for the relative outer shell spelling because policy selection misses it.

## Phase 0 — Freeze the real post-fix evidence

1. Preserve the exact stderr/audit events from both latest invocations.
2. Capture the actual normalized adapter plan in bounded audit/debug output; do not infer it from the historical fixture.
3. Record the command request's normalized working directory and exact outer `bash -c` argv.
4. Characterize the Rose path without entering a sandbox:
   - `pwd -P`;
   - `namei -l /scratch/theo/qshell-project/qshell`;
   - `readlink -f /scratch/theo/qshell-project/qshell`;
   - `findmnt -T` for `/scratch` and the project path.
5. Do not run Vivado or another live canary during this phase.

Deliverable: a sanitized fixture describing path components, symlinks, and mount boundaries needed to reproduce Rose.

## Phase 1 — Prove and fix post-pivot CWD preservation

Relevant code:

- `internal/composition/bwrap_parser.go`
- `internal/composition/broker_linux.go`
- `cmd/agentsh-composition-mount-helper/main.c`
- `cmd/agentsh-bwrap-adapter/main_linux.go`

Tasks:

1. Assert the normalized plan contains `/scratch -> /scratch` before `plan.Cwd` is used.
2. Add a fixture where the requested CWD is an ordinary deep descendant of a recursive bind.
3. Add symlink and separate-submount variants matching Rose if applicable.
4. Verify `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` is rooted at the requested source directory and retains ordinary directory descendants after `move_mount`.
5. Verify no later plan operation or command-jail mask covers a CWD component.
6. Add post-pivot CWD validation before the broker reports success or before payload exec. Use a pinned target identity and avoid stale pre-pivot root descriptors.
7. Return a typed `E_COMPOSITION_*` failure that names the first missing/unresolvable CWD component and relevant operation index without exposing unrelated topology.
8. Prove the exact captured QShell plan reaches its requested CWD.

Do not paper over this by creating an empty CWD path in the synthetic root. The CWD must resolve to the intended admitted source object.

## Phase 2 — Replace root-only bind reduction with heterogeneous rights semantics

Current problem:

```go
if !pathAllowed(canonical, WriteRoots) || rootRights lacks WRITE_FILE {
    recursively force MOUNT_ATTR_RDONLY
}
```

This is conservative for `/nix`, but wrong for a containing source such as `/scratch` with writable project descendants.

Tasks:

1. Enumerate retained policy objects and effective write grants beneath each recursive bind source.
2. Separate VFS mount attributes from Landlock object authority in the model.
3. Prove whether preserving a VFS `rw` bind is safe when:
   - the payload remains in the mandatory base Landlock domain;
   - source objects retain their original Landlock rights through bind aliases;
   - the un-Landlocked helper performs topology changes only and never content mutation;
   - destination ancestry cannot add rights beyond source objects.
4. If mount-level reduction remains desirable, make it subtree-aware. Do not flatten mixed descendant rights to the root's rights.
5. Keep `/nix` effectively read-only and executable as allowed.
6. Preserve writes only inside the project-authorized `/scratch` descendants.
7. Add adversarial alias tests showing writes elsewhere remain denied.
8. Retain source/final mount inventory and restrictive submount attribute checks.

Deliverable: a documented theorem and tests for mixed-rights recursive source trees.

## Phase 3 — Add working-directory-aware command selection

Relevant code:

- `pkg/types/exec.go`
- `internal/api/core.go`
- `internal/policy/model.go`
- `internal/policy/engine.go`
- `internal/policy/overlay.go`
- downstream `nix-config/modules/agentsh-policies/lib/fragments/commands.nix`
- downstream project overlay

Tasks:

1. Decide on a typed command-rule CWD/project-root condition or trusted `exec_bash` normalization.
2. Normalize and resolve `ExecRequest.WorkingDir` before command decision without allowing symlink escape or lexical ambiguity.
3. Include the normalized CWD in command policy evaluation and explain/audit output.
4. Allow project overlay selection only when both command intent and trusted project location match.
5. Cover:
   - absolute `cd /scratch/theo/qshell-project/qshell && nix develop ...`;
   - relative `cd qshell && nix develop ...` from the project root;
   - `cd ./qshell`;
   - request CWD already equal to QShell;
   - expected quoting/spacing variants;
   - negative invocations from outside the trusted project.
6. Preserve first-match precedence of privilege, destructive, hardware, Git, and network gates.
7. Ensure the direct `nix` rule remains useful for non-shell API calls.
8. Never attach composition to arbitrary Bash command trees.

Deliverable: generated-policy and AgentSH unit coverage proving equivalent safe forms select the same request-local composition mode.

## Phase 4 — Build the actual release gate

Add a deterministic Nix check that combines all layers:

1. packaged AgentSH, including Nix `makeWrapper`;
2. exact started wrapper PID configuration before ACK/READY/GO;
3. Rose-equivalent host composition ceiling;
4. project-only write roots and non-writable `/nix`;
5. generated pi-supervised policy plus a real project overlay at its trusted boundary;
6. Pi-style outer `bash -c` submission and request working directory;
7. absolute and relative command forms;
8. exact captured Bubblewrap 0.11.2/QShell argv;
9. Rose-equivalent `/scratch` topology;
10. post-pivot CWD and project write assertions;
11. `/nix` and `/nix/store` write-denial assertions;
12. source command/file/metadata laundering denials;
13. hidden control/proc/cgroup checks;
14. repeated and recursive composition;
15. assertion that real Bubblewrap never executes and no Bubblewrap approval is emitted.

Keep the existing lower-level VM checks. This new gate is additive and is the only gate that authorizes another Rose canary.

## Phase 5 — Validation sequence

Run through flake outputs:

- AgentSH package;
- formatting and unit checks;
- Linux/amd64 compile;
- module evaluation;
- lower-level Landlock/recursive/namespace VMs;
- complete nested production broker VM;
- new Pi/QShell integration gate;
- downstream generated policy boundary checks and Rose/non-Rose evaluations.

Record logs and exact output paths in the parent issue.

Phase 5 passed for `ce42938d6bea6e7d644fd342f14b4b5975d2a8d1`. The canonical commands, logs, and Nix store outputs are recorded in `issues/qshell-bubblewrap-composition-live-rollout-gaps.md`. The gate additionally caught and fixed recursive composition through a preserved ancestral PID namespace by deriving its real owner with `NS_GET_USERNS`.

The first deployed harmless canary then exposed a release-gate qualification gap: the gate replayed argv generated outside AgentSH, while Nixpkgs generates top-level identity binds by enumerating `/*` inside the command. AgentSH `83944d43` replaces replay-only qualification with in-boundary argv generation, admits exact list-only roots without `READ_FILE`, excludes `/` from bind-source authority, and re-passes the complete Phase 5 matrix. This supersedes the earlier Phase 5 release authorization; only the strengthened gate authorizes the next rollout.

## Phase 6 — Controlled rollout

Only after Phase 5 passes:

1. commit/push AgentSH;
2. update/push the downstream `flake.lock`;
3. apply Home Manager on Rose only;
4. install the reviewed project overlay;
5. start a fresh Pi session;
6. run `nix develop .#ultrascale --command true`;
7. confirm no real Bubblewrap approval or `overflowuid` error;
8. run `vivado -version` once;
9. stop on any new `E_COMPOSITION_*` result and bring the full evidence back into the deterministic gate.

Do not run hardware operations.

## Completion criteria

- Exact QShell CWD survives pivot.
- Heterogeneous `/scratch` rights are preserved without broadening authority.
- `/nix` remains non-writable.
- Equivalent reviewed outer command forms select composition; unrelated Bash does not.
- The packaged end-to-end Nix gate passes.
- Harmless Rose canary succeeds before `vivado -version`.
- Vivado prints a version without hardware access.
- Other hosts remain unchanged.
