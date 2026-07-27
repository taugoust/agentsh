# Nethelper reaper races live command cleanup and permanently disables strict execution

## Status

Open. Root cause identified on 2026-07-27. A narrow source fix and regression tests are present in the working tree but have not been formatted, built, or run because the affected supervisor is already fail-closed.

## Problem

The privileged nethelper's periodic registration reaper can clean a newly empty command cgroup while its owning AgentSH supervisor is still alive and about to perform the normal authenticated cleanup. The supervisor's cleanup RPC then receives:

```text
session cgroup is not registered with this helper
```

AgentSH treats that response as an uncertain kernel-resource cleanup failure and permanently changes session network readiness to `failed`. Every later command is refused under strict enforcement, including commands requested by child Pi processes. This can strand all subagents in the session.

The command may already have run successfully before the cleanup race. Nevertheless, the current API-facing error says that the command was not executed and that setup failed before resume. That is an incorrect and potentially unsafe dispatch classification.

## Observed incident

Session:

```text
session-db65d31a-a8eb-4d97-b26e-8ac2a4a2b217
```

Affected command:

```text
cmd-846f5a4e-cff0-43d8-a006-ee52e2e49b12
```

The command was owned by subagent `subagent-aba7193b-ae0f-4948-8cd9-ed786b2752c0` and ran:

```text
bash -c "nl -ba /tmp/linux-namei.c | sed -n '4538,4615p'"
```

Audit ordering proves that user code started and performed filesystem operations:

1. `cgroup_applied` at `2026-07-27T10:22:14.98623188Z`.
2. `network_enforcement_active` at `2026-07-27T10:22:14.999712262Z`.
3. `command_started` at `2026-07-27T10:22:14.999903832Z`.
4. The shell and `sed` executed and opened `/tmp/linux-namei.c` through `2026-07-27T10:22:15.008138975Z`.
5. `network_enforcement_inactive` was emitted at `2026-07-27T10:22:15.012347234Z`.
6. `network_enforcement_cleanup_failed` immediately followed at `2026-07-27T10:22:15.012459117Z` with `nethelper cleanup registration: session cgroup is not registered with this helper`.
7. A sticky `network_enforcement_failed` event followed at `2026-07-27T10:22:15.013114143Z`.
8. `command_finished` reported exit code 0 plus the cleanup error at `2026-07-27T10:22:15.013234687Z`.

The externally surfaced message was nevertheless:

```text
AgentSH pre-execution/helper enforcement failed. strict network enforcement is not ready; command was not executed: command network setup failed before resume: post-start cleanup: nethelper cleanup registration: session cgroup is not registered with this helper
```

After this transition, ordinary Bash commands could no longer start in the session.

## Root cause

`internal/nethelper/transport.go` runs `Server.serveReaper` periodically, normally every five seconds. It asks `SupervisorAuthorizer.ReapableRegistrations()` for registrations to clean.

`internal/nethelper/authorizer.go` previously made every active, non-in-flight registration reapable as soon as its command cgroup was observed unpopulated. It did not require the retained supervisor process identity to be dead.

Normal command teardown creates this sequence:

1. The command exits, making its cgroup unpopulated.
2. The live supervisor returns from `cmd.Wait()` and prepares its cleanup RPC.
3. If the periodic reaper runs in this small interval, it marks the registration `CleanupPending`, cleans the helper backend, and removes the authorizer registration.
4. The live supervisor sends its exact authenticated cleanup request using the original registration ID, cgroup ID, and path.
5. Authorization fails because the reaper already removed the registration.
6. `applyCgroupV2` reports an uncertain cleanup failure, and `recordNetworkCleanupFailure` makes strict readiness sticky-failed.

The incident occurred directly on a reaper boundary and matches this control flow. The backend orphan-pin reaper is not the competing path: it skips cgroup IDs owned by active in-memory registrations.

The in-memory behavior also conflicts with `pinnedRegistrationReapable()` in `internal/nethelper/kernel_linux.go`, which deliberately retains an unpopulated pin tree while its supervisor is alive.

## Impact on subagents

This is not merely a network-cleanup diagnostic:

- All child Pi processes point back to the same AgentSH session.
- Once strict readiness becomes sticky-failed, their Bash calls are refused.
- One parallel child in the incident later settled without visible final assistant text after its command path failed.
- A later focused child was explicitly given `600000` ms and ended after `600036` ms as `timed_out`; this was the requested ten-minute deadline firing, not a hidden shorter timeout. It ran after the session had already lost command execution.
- Parent-side symptoms therefore include missing final handoff, apparently hung children, and exact-deadline timeouts even though the initiating defect is the shared supervisor's cleanup race.

The missing final-text protocol outcome may still deserve independent hardening, but it should not be diagnosed in isolation from the earlier command-boundary failure.

## Security and lifecycle invariants

The fix must preserve these properties:

1. A live supervisor owns normal teardown for its command registrations.
2. Failed-registration tombstones remain immediately reapable so failed setup can be compensated.
3. A normal registration is automatically reaped only after the retained supervisor process identity is proven dead and the command cgroup is gone or unpopulated.
4. A populated orphan remains pinned and fail-closed even after supervisor death.
5. Missing or unverifiable supervisor identity is not evidence of death.
6. An uncertain cleanup result still fails closed; `not registered` must not be blindly converted to success because helper restart or lost state could leave pinned resources.
7. Any post-start cleanup failure must be reported as a started command. It must never be labelled safe to replay or “not executed.”

## Working-tree fix

The current unvalidated changes do the following:

- `internal/nethelper/authorizer.go`
  - retain an unpopulated normal registration while its supervisor identity is alive or cannot be proven dead;
  - continue to reap failed-registration tombstones immediately;
  - reap normal registrations with reason `orphan-reaped` only after supervisor death is proven.
- `internal/nethelper/authorizer_test.go`
  - add regression coverage that an unpopulated registration without proof of supervisor death is not marked cleanup-pending;
  - preserve immediate failed-registration cleanup coverage.
- `flake.nix`
  - include the new regression tests in the focused `nethelper-lifecycle-tests` check.

These edits are not committed or pushed.

## Remaining corrections

The primary race fix should be accompanied or followed by two outcome/audit corrections:

- Do not emit `network_enforcement_inactive` with a successful-cleanup description when helper/eBPF cleanup has already failed. Record attachment end only after the entire cleanup succeeds.
- Keep post-start cleanup failures distinct from pre-exec setup/release failures. The command-start bit and dispatch state must remain authoritative even when cleanup later makes network readiness sticky-failed.

## Validation

Run through Nix, not direct `go test`:

```bash
cd /home/taugoust/Workspace/agentsh
nix build --no-link .#checks.x86_64-linux.nethelper-lifecycle-tests
nix build --no-link .#checks.x86_64-linux.go-format
nix build --no-link .#checks.x86_64-linux.go-unit-tests
```

Then perform a live strict-network smoke test which repeatedly ends short commands across several nethelper reaper ticks. Required results:

- every command records one successful helper cleanup;
- no cleanup receives `session cgroup is not registered with this helper`;
- session readiness returns to `ready` after each command;
- a subsequent command and a command-using subagent both execute normally;
- no completed command is reported as unstarted.

## Current recovery limitation

The source change cannot repair the already-running supervisor binary or clear its deliberately sticky failed evidence. A fresh supervised AgentSH session is required before formatting, Nix validation, commit, and push can be completed.
