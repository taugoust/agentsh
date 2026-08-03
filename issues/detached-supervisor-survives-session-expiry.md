# Detached supervisors survive session expiry and keep heartbeating indefinitely

## Status

Implemented and validated in the AgentSH and downstream `nix-config` working trees on 2026-08-03. Deployment, inspection of retained shadow work, and cleanup of the six incident units remain pending; no live unit, workspace, lifecycle journal, or remote helper was stopped while implementing the fix.

The implementation makes `stopping` an absorbing durable decision, exits the detached server cleanly when its exact session expires or is explicitly destroyed, supports caller-preallocated IDs, makes exact protocol-v2 404 stop narrowly idempotent, and moves liveness to a 30-second advisory heartbeat. Downstream wrappers now journal the exact identity before dispatch, serialize project startup registration, retain per-session review registrations, and bind SSH keepalive controllers to owner/lifecycle deadlines.

## Severity

High for detached Pi deployments on laptops and long-lived user managers.

An expired session is no longer usable, but its per-session supervisor can remain alive indefinitely. Each protocol-v2 supervisor persists a crash-durable heartbeat every two seconds, so several empty supervisors continuously consume CPU, memory, filesystem I/O, and wakeups. The same lifecycle gaps can also retain an SSH keepalive controller after an interrupted remote startup.

This is not evidence that AgentSH holds a systemd sleep inhibitor. It is evidence of sustained background activity that prevents deep idle and increases package/storage/network wakeups.

## Summary

Detached supervisors are intended to own exactly one AgentSH session. The configured session reaper correctly removes that session after its absolute or idle timeout, closes its runtime resources, and emits `session_expired`. It does not connect that terminal session decision to the detached supervisor lifecycle.

After expiry, the observed protocol-v2 state is contradictory:

- `GET /api/v1/sessions` returns `[]`;
- `GET /api/v1/sessions/<exact-id>` returns `404 {"error":"session not found"}`;
- `GET /api/v1/detached/status` still reports the exact supervisor as `lifecycle_state: ready`;
- `metadata.json` remains `state: ready` and its heartbeat advances every two seconds;
- `supervisor.sock` and the transient user unit remain live;
- `agentsh session stop <exact-id>` cannot complete because the destroy RPC returns 404 before the CLI reaches the exact unit stop.

The supervisor therefore becomes an empty, permanently heartbeating process. `Restart=on-failure` and `RuntimeMaxSec=infinity` make the lifecycle entirely dependent on an explicit successful stop.

## Confirmed local incident

### Deployed identities

The current source and `nix-config` pin both point to AgentSH:

```text
4fb4aa795da73642665dad3b43a5cd7d331c396d
```

The local `nix-config` checkout was:

```text
95f5512d4d6b
```

The six surviving supervisors were started by several earlier store builds, including the current protocol-v2 implementation and one older pre-v2 implementation. The current source still contains the reaper/stop behavior described below.

### Surviving units

Five units started on 2026-07-28 and one on 2026-07-31:

| Session | Policy | Created (UTC) | Expired (UTC) | Expiry cause | Current API sessions |
|---|---|---:|---:|---|---|
| `session-263e8126-ceb1-44b3-bbb2-f09736a5753d` | `pi-supervised` | 2026-07-28 07:40 | 2026-07-30 07:41 | `idle_timeout` | `[]` |
| `session-01efa838-17ca-4d61-94a4-9ea527dba3e5` | `pi-supervised` | 2026-07-28 07:42 | 2026-07-30 07:42 | `idle_timeout` | `[]` |
| `session-ef350b77-b9f4-408a-a553-23b8d5ccce62` | `pi-supervised` | 2026-07-28 07:59 | 2026-07-30 07:59 | `idle_timeout` | `[]` |
| `session-4ed2af2e-08c1-4b89-828c-472f629cec21` | `pi-autonomous` | 2026-07-28 20:11 | 2026-07-30 20:12 | `idle_timeout` | `[]` |
| `session-9dee14e6-fa3b-4e5d-8ee2-b662df89eed9` | `pi-autonomous` | 2026-07-28 20:20 | 2026-07-30 20:21 | `idle_timeout` | `[]` |
| `session-0d52b565-50d0-4a1f-9b50-629064475b99` | `pi-supervised` | 2026-07-31 15:17 | 2026-08-02 15:48 | `idle_timeout` | `[]` |

The configured policy lifetimes are downstream values from `nix-config/modules/agentsh-policies/lib/lifetimes.nix`:

```text
idle_timeout:    48h
session_timeout: 168h
```

Every retained event log contains a terminal event of this shape:

```json
{
  "type": "session_expired",
  "fields": {
    "expired_by": "idle_timeout",
    "idle_timeout": "48h0m0s",
    "session_timeout": "168h0m0s"
  }
}
```

Five protocol-v2 supervisors still had `metadata.json` with `state: ready`; the old first supervisor had no remaining metadata file but retained its socket, service, audit store, and process.

### Resource impact

At the time of inspection, the six empty units accounted for approximately:

```text
CPU time:  13,929 seconds (3.87 CPU-hours)
memory:    370 MiB
tasks:     96
live CPU:  roughly 0.4-0.5% per supervisor
```

A six-second `/proc/<pid>/io` sample showed each of the five protocol-v2 supervisors writing 221,184 bytes, about 36 KiB/s each on the observed filesystem. Their combined write accounting increased by approximately 1.1 MiB over six seconds even though they had no sessions or commands.

The source of this activity is the detached heartbeat:

- `internal/cli/supervisor_session.go` creates a two-second ticker backed by `context.Background()`;
- `internal/detached/recovery.go` updates `metadata.HeartbeatAt` on every tick;
- `internal/detached/metadata.go` serializes the complete metadata object to a temporary file, calls `Sync`, renames it, opens the parent directory, and calls directory `Sync`.

The heartbeat is valuable while a supervisor owns a recoverable live session. It is pure waste after that session has expired, and its current durable write cadence is expensive even for valid idle sessions.

## Root cause in AgentSH

### 1. Session expiry is not coupled to detached supervisor expiry

`internal/server/server.go` derives `sessionTimeout` and `idleTimeout` from policy limits and optional configuration caps. `Server.Run` starts the reaper whenever either limit is non-zero.

`Server.reapOnce` currently:

1. calls `App.ReapExpiredSessions`;
2. removes each expired session from the manager;
3. closes DB proxy, namespace, proxy, workspace, and runtime resources;
4. emits `session_expired`;
5. returns to the reaper loop.

It does not:

- identify that the reaped session is the exact session represented by `App.detachedRuntime`;
- persist `LifecycleStopping` or another terminal expiry transition;
- request `Server.Run` shutdown;
- remove `supervisor.sock`;
- let `runDetachedSupervisor` finish cleanly;
- stop or collect the transient systemd unit.

The manager is now empty, but the HTTP server and heartbeat goroutine remain live.

### 2. Detached status and metadata become false lifecycle evidence

The runtime coordinator is only updated by explicit API teardown, review finalization, recovery failures, and supervisor failures. The generic session reaper never updates it.

Consequently, the runtime continues publishing `ready` after its exact session has disappeared. This defeats the purpose of protocol-v2 lifecycle identity: the session ID, generation, incarnation, PID identity, socket, and heartbeat are authentic, but the reported lifecycle no longer reflects whether the represented session exists.

This is related to, but more specific than, `issues/detached-supervisor-metadata-lifecycle.md`.

### 3. Exact stop is not idempotent after expiry

`internal/cli/supervisor_session.go:stopDetachedSessionExact` performs this sequence:

1. read exact metadata;
2. validate the exact runtime handshake through the captured socket;
3. call `DestroySession`;
4. stop the metadata-recorded systemd unit;
5. acquire the exact runtime lock and persist `stopped`.

If the session reaper already removed the session, step 3 returns 404 and the function returns immediately. It never reaches the exact unit stop even though the preceding runtime handshake proved that the socket belongs to the requested session ID/generation/incarnation.

Downstream wrappers deliberately ignore the stop command's text/status and independently require terminal API evidence, an absent socket, and an inactive/absent exact unit. That fail-closed verification is correct. With the current AgentSH behavior it can never succeed after expiry because the supervisor keeps its socket and unit active.

### 4. Systemd detachment makes missed cleanup durable by design

The delegated launch uses a transient user service with:

```text
Restart=on-failure
RuntimeMaxSec=infinity
KillMode=mixed
TimeoutStopSec=10s
CollectMode=inactive-or-failed
```

The unit is intentionally independent of the Pi wrapper's process tree. Parent death, terminal loss, `pkill pi`, or a wrapper `SIGKILL` therefore cannot stop it. That is necessary for crash recovery and retained `pi-auto` review sessions, but it requires AgentSH to own a complete terminal lifecycle.

A bare `RuntimeMaxSec` is not a sufficient fix. If systemd sends `SIGTERM` while the detached runtime still says `ready`, `runDetachedSupervisor` converts the clean server return into `supervisor exited before a durable stop transition`; `Restart=on-failure` can then rehydrate the expired session. Expiry must be persisted as terminal before shutdown.

## Downstream `nix-config` findings

These findings amplify the AgentSH bug but do not replace the required upstream fix.

### `pi-auto` intentionally retains a live supervisor after Pi exits

`packages/pi-auto/pi-auto.sh` documents that Pi exit keeps the shadow workspace for later `diff`, `accept`, or `reject`. It sets `local_nethelper_retained=1` or `remote_nethelper_retained=1`, causing the EXIT trap to retain the session rather than stop it.

The two `pi-autonomous` units above are therefore expected to outlive their Pi UI initially. The documented bounded fallback is the session/helper lifetime. Once the 48-hour idle timeout expires, however, the AgentSH bug leaves an empty supervisor forever.

There are also two retained `pi-auto` lifecycle records for the same real project and no valid project registration: the corresponding project JSON is a zero-byte file. The cause of that file state was not established, but it makes the sessions harder to resolve through normal `pi-auto diff/accept/reject` lookup. `nix-config/issues/pi-auto-review-session-ambiguity.md` already tracks the broader multiple-session ambiguity.

### Interrupted startup can lose the only exact session identity

Both `pi-supervised` and `pi-auto` currently write a protected startup journal, mark dispatch as `dispatched-unknown`, invoke:

```text
agentsh session start --detach ... --json
```

and only then parse the server-generated session ID and supervisor socket from stdout.

If the CLI/wrapper is interrupted after systemd accepted the unit but before the JSON response is durably captured, the journal intentionally refuses to guess or adopt a discovered session. Three local retained journals match the first three leaked supervisors by start timestamp and workspace exactly. Each remains:

```json
{
  "session_id": "",
  "status": "startup-pending",
  "dispatch_state": "dispatched-unknown"
}
```

A fourth journal records the same condition for a remote startup on `rose.dos` on 2026-07-29.

This safety behavior is preferable to stopping or adopting an unrelated session, but the protocol should not require ambiguity. AgentSH should accept a caller-preallocated validated detached session ID, allowing the wrapper to persist the exact ID, expected state directory, socket, and unit before dispatch.

### Remote SSH keepalive controllers have no owner or absolute lifetime

The interrupted remote startup left a local process:

```text
pi-agentsh-recover --keepalive-controller rose.dos <control-socket>
```

It had been reparented to PID 1 and remained alive from 2026-07-29 through the inspection. Its controller loop in `packages/pi-agentsh-recover/pi-agentsh-recover.sh` is `while true`; it reconnects after every SSH exit and configures `ServerAliveInterval=10`. Its generation counter had reached 75,009.

The controller is explicitly stopped only by exact wrapper cleanup. It does not independently observe:

- the originating wrapper process identity;
- the startup journal reaching a terminal state;
- the helper hard expiry;
- a maximum controller lifetime;
- an orphan grace period.

This process consumed little CPU but maintained recurring process/network wakeups and can survive the remote helper/session it was created to support.

## Evidence from the 2026-08-02 manual cleanup

The retained Pi transcript records a request to kill old Pi sessions. The generated cleanup script:

1. identified the Pi process hosting that conversation;
2. collected process groups for every other process with `comm=pi`;
3. sent `SIGTERM` to eight process groups;
4. waited two seconds;
5. sent `SIGKILL` to groups still containing a Pi process.

This removed the visible/wrapper Pi processes but did not target:

- user-systemd `agentsh-supervisor-session-*.service` units, which have separate sessions/process groups;
- `pi-agentsh-recover --keepalive-controller`;
- SSH master/proxy children owned by that controller.

The user journal shows only one detached supervisor stopping during that cleanup:

```text
session-290330fe-21b0-494b-b22f-24acc0d55741
```

Systemd reported that single unit had consumed 1h20m42s CPU over 1w2d wall time. The six units listed above remained active.

The two-second forced-kill grace can also interrupt wrapper cleanup before AgentSH's ten-second unit stop bound, but all six surviving sessions had independently logged `session_expired` before this investigation. The manual kill exposed and failed to remove the leak; it did not cause the reaper defect.

## Expected behavior

For a detached supervisor that owns exactly one session:

1. Absolute or idle session expiry is a durable terminal lifecycle decision.
2. The exact runtime enters `stopping` before the session identity is removed from the in-memory manager.
3. Session resources and helper registrations are cleaned under the existing topology/cleanup synchronization.
4. `session_expired` is durably emitted with the exact cause.
5. The server stops accepting work and shuts down its listeners.
6. `runDetachedSupervisor` observes the durable terminal transition, records `stopped` (or a distinct terminal `expired` state), and exits successfully.
7. `Restart=on-failure` does not restart the intentionally expired session.
8. Systemd collects the transient unit and the heartbeat stops.
9. Shadow workspace retention follows explicit `KeepOnDestroy`/review semantics; process expiry must not silently delete reviewable changes.
10. A later exact stop request is idempotent and can complete cleanup even when the API session is already absent.

## Safety invariants

Any fix must preserve these properties:

1. Never stop, recover, or adopt a session based only on workspace/path similarity.
2. Verify exact session ID, protocol, generation, incarnation, and process/unit identity before treating a 404 as already destroyed.
3. Persist terminal expiry before shutting down; do not let `Restart=on-failure` resurrect an expired session.
4. Do not delete a retained shadow workspace merely because its active control process expires.
5. Serialize expiry with helper rebinding, in-flight command cleanup, review finalization, and explicit destroy.
6. Refuse terminal transition if durable lifecycle persistence fails before session removal; do not first delete the only live session and then discover that terminal state cannot be recorded.
7. Revoke child capabilities, close approval UI state, clear scoped approvals as defined by expiry policy, and terminate any owned command trees exactly once.
8. Remove or rotate detached event authority at terminal transition.
9. Do not convert arbitrary destroy failures into success. Only identity-checked `session not found` is idempotent-stop evidence.
10. Keep remote helper release authenticated and identity-specific; never release a helper merely because the local wrapper disappeared.

## Implemented AgentSH design

### 1. Add detached-aware terminal reaping

Do not bolt supervisor shutdown onto the end of the current `reapOnce` after the manager has already deleted the session. Introduce an expiry transaction that can:

1. identify expired candidates without removing them;
2. acquire the existing session-topology lock;
3. resolve/stabilize candidate helper cleanup;
4. if the candidate matches the installed detached runtime, persist `LifecycleStopping` or `LifecycleExpired` first;
5. remove and close the session;
6. emit terminal evidence;
7. signal `Server.Run` to shut down after the transaction commits.

The server needs a typed internal terminal signal rather than treating listener closure as a failure. `runDetachedSupervisor` should map the committed expiry state to a successful process exit.

A distinct `expired` terminal state may be clearer than overloading `stopped`, provided protocol consumers and recovery explicitly reject it as terminal.

### 2. Make exact stop idempotent after session absence

After a successful exact detached-runtime handshake, classify `DestroySession` outcomes:

- success: continue exact unit teardown;
- typed `session_not_found`: treat the session as already destroyed and continue exact unit teardown;
- conflict, helper-cleanup uncertainty, authorization failure, transport ambiguity, or wrong identity: fail closed.

Then stop the metadata/manifest-recorded exact unit, acquire the runtime lock, clear socket/event authority, and persist terminal metadata/manifest state.

This should work whether stop is invoked through the live socket, through metadata discovery, or after a wrapper resumes retained cleanup.

### 3. Support caller-preallocated detached session IDs

Add an optional strict CLI flag such as:

```text
agentsh session start --detach --session-id session-<uuid> ...
```

Requirements:

- validate the canonical `session-UUID` form;
- reject path separators, aliases, malformed UUIDs, and existing conflicting state;
- use the supplied identity for state directory, socket, unit, manifest, and create request;
- never silently replace an existing session;
- make interrupted retries report/reconcile the exact existing provisioning identity rather than creating another ID.

The generic session client already supports create requests with explicit IDs. Detached startup currently discards that opportunity by always generating its UUID internally.

### 4. Reduce heartbeat write amplification

Even valid idle detached sessions should not require a full data-and-directory `fsync` every two seconds solely for liveness.

Evaluate one or more of:

- a slower configurable heartbeat interval;
- a separate small volatile heartbeat file;
- atomic replacement without durability sync for heartbeat-only updates;
- durable sync only on lifecycle/generation/incarnation transitions;
- coalescing heartbeat with other metadata mutations.

Crash recovery authority must remain durable, but a liveness timestamp can tolerate losing its latest tick after a crash. Tests should separate durable lifecycle state from advisory heartbeat freshness.

### 5. Add empty-supervisor defensive checks

Protocol-v2 status should never advertise `ready` when the exact session is absent. As defense in depth:

- derive readiness from both runtime state and exact manager membership;
- expose a typed terminal/inconsistent status if they diverge;
- fail closed on command/mutation admission;
- request bounded supervisor shutdown rather than heartbeating indefinitely.

This is not a substitute for transactional expiry, but it prevents false lifecycle reporting if another path removes the session.

## Implemented downstream `nix-config` follow-up

After AgentSH exposes caller-preallocated IDs and terminal expiry:

1. Persist the exact session ID, expected socket, and expected systemd unit in the startup journal before dispatch.
2. Reconcile only that identity after interrupted local or SSH startup.
3. Make `pi-auto` refuse to silently overwrite an unresolved project registration; require resume, diff, accept, reject, or an explicit reviewed replacement.
4. Add `pi-auto sessions` and exact stale-session cleanup with diff/workspace preservation, as already proposed in `pi-auto-review-session-ambiguity.md`.
5. Give SSH keepalive controllers a durable owner/lease contract and an absolute deadline tied to helper hard expiry plus cleanup slack.
6. On wrapper death, allow an orphan grace period for exact recovery, then stop the controller without releasing remote helper state unless release is independently authenticated.
7. Never use `pkill pi` as lifecycle cleanup; provide an exact wrapper command that enumerates session/unit/controller identities and preserves review state.

Parking a `pi-auto` review session immediately after Pi exits may further reduce laptop load, but it requires a distinct recoverable parked state. It must not misuse `session stop`, which currently means teardown rather than suspend-for-review.

## Deterministic reproduction

Add a focused fixture with very short policy limits and a fake clock where possible:

1. Start one protocol-v2 detached supervisor with one exact session.
2. Advance beyond idle timeout and invoke one reaper pass.
3. Observe the current defect:
   - session list becomes empty;
   - exact session GET returns 404;
   - detached status remains `ready`;
   - socket and process remain live;
   - metadata heartbeat continues;
   - exact stop returns before stopping the unit.
4. In the fixed implementation, require:
   - terminal lifecycle persisted before manager removal;
   - one `session_expired` event;
   - listeners close;
   - socket disappears;
   - supervisor exits successfully;
   - no systemd restart;
   - retained shadow state remains according to policy.

Avoid wall-clock sleeps in unit tests. Expose a reaper/expiry transaction callable with an injected `now`, and use a bounded NixOS VM only for the real transient-unit exit behavior.

## Validation

Run only through Nix-native checks per repository policy.

### AgentSH focused checks

Add or extend checks covering:

- detached expiry transaction and durable ordering;
- exact stop after identity-checked session 404;
- terminal status/metadata consistency;
- no recovery of expired state;
- retained-shadow behavior;
- heartbeat cessation;
- caller-supplied session ID validation and collision handling.

Candidate commands after the checks exist:

```bash
cd /home/taugoust/Workspace/agentsh
nix build --no-link .#checks.x86_64-linux.detached-supervisor-expiry-tests
nix build --no-link .#checks.x86_64-linux.detached-supervisor-systemd-recovery
nix build --no-link .#checks.x86_64-linux.go-format
nix build --no-link .#checks.x86_64-linux.go-unit-tests
nix build --no-link .#agentsh
```

The NixOS user-systemd VM should prove that an expired transient unit exits cleanly and is not restarted by `Restart=on-failure`.

### Downstream wrapper checks

Extend `nix-config` smoke tests to cover:

- interruption before start dispatch;
- interruption after unit creation but before JSON capture;
- retry/reconciliation using a preallocated exact ID;
- ordinary `pi` exit;
- retained `pi-auto` exit followed by idle expiry;
- `diff`/`accept`/`reject` after process expiry;
- exact cleanup after API session absence;
- keepalive controller orphan grace and hard deadline;
- multiple unresolved sessions for one project.

## Acceptance criteria

- [x] Expiring the only session causes its detached supervisor to enter a durable terminal state and exit.
- [x] The corresponding transient user unit becomes inactive/collected and does not restart.
- [x] `GET /api/v1/detached/status` never reports `ready` when the exact session is absent.
- [x] `metadata.json` and `recovery.json` agree on the terminal state and no longer carry active event authority.
- [x] `agentsh session stop <exact-id>` succeeds idempotently after an identity-checked session 404.
- [x] Arbitrary 404s, wrong sockets, identity mismatches, and ambiguous transport failures remain fail-closed.
- [x] Expiry is serialized with helper rebind, review finalization, and active command cleanup.
- [x] Expired and `stopping` sessions are never automatically recovered or replaced.
- [x] Retained shadow work remains reviewable according to explicit policy without requiring an empty supervisor to run forever.
- [x] Detached startup can use an exact ID persisted by the caller before dispatch.
- [x] Interrupted startup cannot create an unidentifiable supervisor unit.
- [x] Heartbeat-only writes no longer force full durable metadata and directory sync every two seconds.
- [x] SSH keepalive controllers have a bounded orphan/absolute lifetime and stop without unauthenticated helper release.
- [x] Deterministic Nix checks cover direct, systemd-delegated, wrapper, `pi-auto`, and interrupted-start paths.
- [ ] Live laptop acceptance shows no empty AgentSH supervisors or orphan keepalive controllers after deployment and reviewed cleanup.

## Current incident cleanup constraint

Do not blindly kill all `agentsh` processes or recursively delete session state.

At inspection time all six local supervisor APIs had empty session lists, but two originated from `pi-auto` shadow workflows and several state directories/lifecycle journals remain the only evidence needed to inspect or recover retained work. The remote startup also retains authenticated helper/recovery identity that must not be guessed or released by path alone.

A safe cleanup procedure should:

1. verify each exact unit/socket/session identity;
2. snapshot or inspect retained shadow changes;
3. stop each empty exact unit without deleting its state directory;
4. reconcile lifecycle/project registrations separately;
5. stop the exact SSH controller through its protected control specification;
6. release any remote helper only through authenticated exact-lease cleanup after remote state is verified.

No such cleanup was performed as part of this investigation.

## Related issues

- `issues/detached-supervisor-metadata-lifecycle.md`
- `issues/detached-supervisor-transport-timeout-sprawl.md`
- downstream `nix-config/issues/agentsh-detached-supervisor-crash-recovery.md`
- downstream `nix-config/issues/pi-auto-review-session-ambiguity.md`
- downstream `nix-config/issues/pi-auto-wrapper-refactor.md`
- downstream `nix-config/issues/pi-ssh-ephemeral-nethelper-expires-before-session.md`
