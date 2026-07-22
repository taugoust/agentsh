# Make QShell Bubblewrap composition pass the real Rose canary

## Status

Open. The composition backend is implemented and enabled only on Rose, but the live non-hardware acceptance command still does not reach Vivado. Do not describe the feature as production-ready or resolved.

Latest deployed/pinned revisions at handoff:

- AgentSH `overlays`: `b1479a2fa521160b9dd706309dd62a35f7719023`
- `nix-config/main`: `5bd4bf3` (pins AgentSH `b1479a2f`)
- policy-boundary placement: `nix-config` `29066f6`
- Rose-only host-ceiling enablement: `nix-config` `6eab7ff`

No hardware command has been authorized or run. The only approved acceptance command is `vivado -version` after a harmless composed-shell canary succeeds.

## User impact

The user has had to discover multiple deterministic integration defects manually on Rose. Treat Rose as an acceptance target, not as the development test harness. The next rollout should happen only after an end-to-end check exercises the packaged supervisor path, realistic Rose policy rights, project overlay selection, and the exact QShell Bubblewrap argv.

## Governing security constraints

- Landlock remains mandatory.
- A nested sandbox may only rearrange or reduce authority from the outer AgentSH command boundary.
- Raw mount-family syscalls, external `setns`, network/time namespaces, unsupported Bubblewrap options, ambiguous topology, and protocol anomalies fail closed.
- Preserve `/nix/store` read-only behavior and source-aware file/metadata/exec policy.
- Approval-gated paths are never broker source authority.
- Composition requires both the Rose-only host ceiling and explicit project-policy selection.
- `/agentsh-composition-scratch` is a dedicated `1733 root:root` top-level directory. It was provisioned manually; automatic trusted provisioning remains deferred.
- Other DOS hosts must remain unchanged.
- Hardware programming, reset, `hw_server`, driver, fleet, KVM, and microVM operations remain out of scope.

## Implemented foundation

AgentSH `585d7e61` introduced the Landlock-preserving Bubblewrap 0.11.2 semantic adapter and authenticated mount-plan broker. It includes:

- exact captured QShell argv and Bubblewrap option fixtures;
- request-local composition selection;
- a strict command jail, complete file/metadata interception, io_uring denial, and source-aware file and exec policy;
- descriptor/pidfd pinning for helpers, wrappers, adapters, requesters, namespace owners, and registry owners;
- authenticated bounded `SCM_RIGHTS` setup of retained Landlock and synthetic-mount objects;
- recursive `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` plus independent source/final mount topology verification;
- private/current PID proc semantics, identity-only `/dev -> /dev`, recursive/repeated transition coverage, and typed `E_COMPOSITION_*` failures.

AgentSH `91a8e51d` fixed setup occurring before the wrapper existed:

- composition configuration is deferred until after `cmd.Start()`;
- the exact started wrapper PID is passed to the notify handler before ACK/READY/GO releases execution;
- Nix `makeWrapper` packages authenticate the actual `.agentsh-unixwrap-wrapped` process image;
- setup failures propagate through the pre-exec readiness channel;
- command-local composition state and retained resources are cleared safely.

AgentSH `b1479a2f` changed a requested read-write bind whose root lacks base write authority into a recursively read-only bind instead of rejecting it. This was intended to admit QShell's `/nix -> /nix` identity bind without granting `/nix` write authority.

## Live rollout chronology

### 1. Composition was not selected for the outer Pi command

Observed:

```text
bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied
```

AgentSH also requested approval for the real Bubblewrap ELF:

```text
/nix/store/zp6rsi809fx5h7dccn7aidg1mj8zgn52-bubblewrap-0.11.2/bin/bwrap
```

Cause: Pi's `exec_bash` submits an outer `bash -c` command. A broad trusted `allow-shell-exec`/runtime allow matched before the project overlay, so composition selected on an inner `nix` rule was never attached to the command tree.

Downstream fix: `nix-config` `29066f6` moved the pi-supervised project command boundary before broad runtime allows while retaining destructive, privilege, hardware, Git, and network gates ahead of it.

### 2. Broker configuration used PID 0 before process start

Observed after composition began selecting:

```text
E_COMPOSITION_REQUESTER_CHANGED: trusted wrapper PID is invalid
```

Cause: `configureExecveComposition` was called during wrapper construction, before `cmd.Start()`, with wrapper PID `0`. `SO_PEERCRED` on an inherited socketpair was not a valid substitute because it describes the creator, not the later inheriting child.

Fix: AgentSH `91a8e51d`, summarized above.

### 3. QShell `/nix -> /nix` was rejected as a writable bind

Observed:

```text
agentsh-bwrap-adapter: E_COMPOSITION_COMMIT_FAILED: plan operation 2 (bind): E_COMPOSITION_RIGHTS_ESCALATION: read-write bind source "/nix" is not base-policy writable
```

Cause: the frozen production VM configured broker `WriteRoots: ["/"]`, unlike Rose. That masked a coarse broker check requiring the root of every Bubblewrap `--bind` to be base-policy writable. QShell requests `--bind /nix /nix`, while Rose intentionally grants no write authority to `/nix`.

Fix attempt: AgentSH `b1479a2f` forces the entire recursive bind read-only when the bind root is not base-policy writable. This removed the live `/nix` rejection.

Important follow-up: this reduction is probably too coarse for heterogeneous trees. QShell also requests `--bind /scratch /scratch`; the root `/scratch` is not itself beneath the project write root, but `/scratch/theo/qshell-project/**` is writable. Making the entire recursive `/scratch` clone read-only removes legitimate descendant write authority. Landlock already enforces rights by object after aliasing, so the next agent should reconsider whether VFS `rw` can safely be preserved when mandatory Landlock remains attached, or derive a subtree-aware reduction rather than checking only the bind root. Do not solve this by granting broad write authority to `/nix` or `/scratch`.

### 4. The composed root now loses the requested working directory

Latest absolute-path canary:

```sh
cd /scratch/theo/qshell-project/qshell && \
  nix develop .#ultrascale --command vivado -version
```

Observed:

```text
agentsh-bwrap-adapter: chdir /scratch/theo/qshell-project/qshell: chdir /scratch/theo/qshell-project/qshell: no such file or directory
```

Exit code was `125`; Vivado never launched.

This proves:

- the outer command selected composition;
- wrapper PID/setup authentication passed;
- the `/nix` rights check no longer stopped plan operation 2;
- the broker reported a successful commit and the adapter entered the resulting root;
- the requested CWD was absent or unresolved only after topology construction/pivot.

The frozen argv does contain all of the following:

```text
--chdir /scratch/theo/qshell-project/qshell
--bind /scratch /scratch
```

Therefore this is not explained by the fixture simply omitting `/scratch`. Investigate the actual live normalized plan and Rose source topology rather than assuming they equal the frozen VM topology.

Required questions:

1. Did the live argv actually include `/scratch -> /scratch`, and did the parser retain it in order?
2. Does any component of `/scratch/theo/qshell-project/qshell` resolve through a symlink or a separate mount on Rose? Capture `pwd -P`, `namei -l`, `readlink -f`, and `findmnt -T` outside the sandbox.
3. Did recursive `open_tree` clone the source directory root expected by the broker, or only a mount whose relative directory view changes after pivot?
4. Did a command-jail mask or later plan operation cover a path component?
5. Does `b1479a2f`'s recursive read-only reduction alter the `/scratch` clone in an unexpected way?
6. Why did pre-pivot final topology validation pass while post-pivot `chdir` returned `ENOENT`?

Add a typed pre-payload validation for `plan.Cwd` in the completed target root. It should report the first missing/unresolvable component and relevant normalized operation/source identity without leaking unrelated host topology. The broker already verifies mount nodes before pivot; coverage must also prove ordinary directory descendants needed by `--chdir` survive pivot.

### 5. Equivalent relative shell spelling bypasses composition

Latest relative-path canary:

```sh
cd qshell && nix develop .#ultrascale --command vivado -version
```

Observed:

```text
bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied
```

Exit code was `1` in about two seconds. This is the real Bubblewrap path, not a semantic-adapter failure.

The project overlay currently selects composition on `bash` only for this exact args shape:

```regex
^-c[[:space:]]+cd[[:space:]]+/scratch/theo/qshell-project/qshell[[:space:]]+&&[[:space:]]+nix[[:space:]]+develop[[:space:]]+\.#ultrascale([[:space:]]|$)
```

It does not match `cd qshell`, `cd ./qshell`, a request whose working directory is already `qshell`, or likely harmless quoting/spacing variants. The direct `nix develop` rule cannot help because Pi's supervised `exec_bash` tool submits `bash -c` as the policy command.

Do not require the user to memorize one magic shell spelling. The selection must remain narrow, but it must combine trusted project-overlay provenance with the request working directory and reviewed `nix develop .#ultrascale` intent. AgentSH command policy currently does not expose a working-directory matcher, although `ExecRequest.WorkingDir` is available. Options to review include:

- add a typed CWD/project-root condition to command rules and evaluate it before first-match resolution;
- normalize the trusted `exec_bash` request into command intent plus working directory before policy matching;
- add narrowly enumerated downstream patterns only as a temporary measure, with generated-policy tests for every supported spelling.

A broad `bash` composition allow is not acceptable. Sensitive base gates must remain ahead of project selection.

## Deterministic test status at handoff

The original `585d7e61` final suite passed package, formatting/unit, Linux/amd64 compile, module evaluation, Landlock mount-graph, recursive-clone, namespace feasibility, and nested production broker checks. However, its production broker fixture used all-writable roots and therefore did not model Rose.

For `91a8e51d`:

- package/format/unit and Linux/amd64 compile passed;
- the nested production VM passed using the packaged Nix `makeWrapper` executable, validating hidden wrapper process identity.

For `b1479a2f`:

- the focused bind-attribute unit test was added and the Go unit check was invoked without a reported unit failure;
- the production VM was changed to use project-only write authority and the exact captured QShell contract;
- one run failed before the broker challenge because the fixture's wrapper workspace still granted `/` write rights while the server ceiling was project-only;
- a subsequent run changed workspace handling too broadly and broke the unrelated generic broker subtest by removing executable authority;
- the final committed fixture scopes the realistic workspace change to semantic composition, but the complete nested VM was **not rerun after that last adjustment**;
- live Rose then advanced past `/nix` and failed at post-pivot `chdir` as described above.

Do not claim the current nested VM or live acceptance passes.

Relevant logs from the development session:

- `/tmp/agentsh-composition-live-fix-vm.log` — first packaged-wrapper VM attempt; failed only because the fixture expected the unwrapped process name.
- `/tmp/agentsh-composition-live-fix-vm2.log` — packaged-wrapper VM pass for `91a8e51d`.
- `/tmp/agentsh-qshell-nix-bind-fix.log` — first realistic-write-root VM attempt; production setup mismatch.
- `/tmp/agentsh-qshell-nix-bind-fix-vm2.log` — second attempt; generic fixture regression before production subtest.

Earlier complete-suite logs remain:

- `/tmp/agentsh-composition-final-suite.log`
- `/tmp/agentsh-composition-vm53.log`

## Required replacement release gate

Before another Rose rollout, add one deterministic Nix check that exercises the actual integration boundary rather than isolated pieces:

1. Build and run the packaged AgentSH wrapper, including Nix `makeWrapper`.
2. Use a generated configuration equivalent to Rose's enabled host ceiling.
3. Merge a real project overlay at the same trusted project boundary as pi-supervised.
4. Submit the same outer `bash -c` shape used by Pi's `exec_bash`, not only a direct adapter or direct `nix` process.
5. Cover both absolute and relative working-directory spellings.
6. Use project-only write roots; `/nix` must remain non-writable.
7. Feed the exact captured 67-operation QShell argv.
8. Model `/scratch` with the same symlink/mount shape as Rose once characterized.
9. Assert that `/scratch/theo/qshell-project/qshell` exists after pivot and is the payload CWD.
10. Assert no approval is requested for the real Bubblewrap and the real Bubblewrap process never runs.
11. Run a harmless mock payload first; then `vivado -version` remains the only live Xilinx canary.
12. Keep non-Rose host evaluation disabled.

The gate should fail on the exact errors seen during rollout: missed composition selection, PID 0/wrong wrapper identity, `/nix` rights rejection, missing post-pivot CWD, and real Bubblewrap fallback.

## Rollout state and operational notes

- `/agentsh-composition-scratch` should remain `1733 root:root`.
- Home Manager must apply the latest `nix-config` pin on Rose.
- A fresh Pi session is required after policy/package changes because the policy snapshot is session-local.
- The project overlay source used during rollout is `/mnt/virtiofs/Workspace/overlay.yaml`; the deployed project copy belongs at `/scratch/theo/qshell-project/.agentsh/policy-overlays/overlay.yaml`.
- The absolute command selecting composition proves that a matching overlay was loaded in that session. The relative command proves its command matcher is incomplete.
- The saved Nix trusted setting for `extra-sandbox-paths` is expected and unrelated.
- The prior session approval for the real Bubblewrap is stale evidence from fallback execution and must not become source authority or a substitute for composition.

## Acceptance criteria

- Both reviewed absolute and relative Pi invocations select the semantic adapter through a narrow project/CWD-aware policy rule.
- The exact QShell plan preserves its requested CWD after pivot.
- `/nix` and `/nix/store` do not gain write authority.
- Project paths retain exactly their outer writable authority through `/scratch` aliasing.
- No real Bubblewrap approval or `overflowuid` error occurs.
- `nix develop .#ultrascale --command true` succeeds first.
- `nix develop .#ultrascale --command vivado -version` prints the version without hardware access.
- All existing Landlock, source-attribution, namespace, network, timeout, and cleanup invariants remain enforced.

## Related downstream documentation

- `nix-config/issues/agentsh-trusted-fhs-sandbox-composition.md`
- `nix-config/issues/plans/agentsh-bubblewrap-0112-qshell-contract.md`
- `nix-config/issues/plans/agentsh-composable-nested-bubblewrap.md`
- `nix-config/modules/agentsh-policies/lib/fragments/commands.nix`
- `/mnt/virtiofs/Workspace/overlay.yaml`
