# Rose detached supervisor exits before publishing its socket

## Status

Open release blocker. The first fresh Rose launch after deploying AgentSH `39aaacb4e52ab27338291162ce2da5c1be080531` through `nix-config` `a32d1b4` timed out before the detached supervisor published its Unix socket. Do not continue to the QShell or Vivado canary until the startup failure is understood and covered by a deterministic regression.

The existing known-good Rose session remains the acceptance reference and must not be stopped or cleaned up while this issue is open. No hardware operation was performed.

## Observed deployment

The failed launch ran `pi` from an SSH shell on Rose in `/scratch/theo/qshell-project`. The activated binaries were:

- Pi: `/nix/store/ja7impirlisygi2qrdzs72qp1y3zi2rd-pi/bin/pi`;
- AgentSH: `/nix/store/qdwghswym7ljjgzkzw652bb8shiqw4cf-agentsh-unstable-2026-06-17/bin/agentsh`.

The wrapper reported `timed out waiting for the supervisor socket`. The retained failed state was:

- session: `session-6444301a-4e6b-4433-9da4-d4b0a437ac3d`;
- state directory: `/scratch/theo/.local/share/agentsh/sessions/session-6444301a-4e6b-4433-9da4-d4b0a437ac3d`;
- expected unit: `agentsh-supervisor-session-6444301a-4e6b-4433-9da4-d4b0a437ac3d.service`;
- systemd invocation: `e1ed9f48bbd44b2a90c4b9595d62d11f`.

`logs/supervisor.log` contained only:

```text
Running as unit: agentsh-supervisor-session-6444301a-4e6b-4433-9da4-d4b0a437ac3d.service; invocation ID: e1ed9f48bbd44b2a90c4b9595d62d11f
```

After the 15-second wait failed, the transient `--collect` unit no longer existed and `systemctl --user status` reported that the unit could not be found. The first journal query accidentally omitted the invocation ID's final `f`, so its empty result is inconclusive and must not be treated as evidence that the correct invocation has no journal entries. The contents of the correct invocation journal and `events.jsonl`/`events.db`, if any, still need to be captured before changing or removing the failed state directory.

## Expected behavior

A schema-3 helper lease should provide the authenticated `composition_scratch_root`, the delegated user supervisor should persist `composition_runtime_provisioned` and `composition_runtime_ready`, and `agentsh session start --detach` should return the session ID and supervisor socket. A fresh Pi session should then run the harmless `nix develop .#ultrascale --command true` canary before any `vivado -version` invocation.

## Actual behavior

`systemd-run --user` accepted the transient service, but the service disappeared before creating `supervisor.sock`. The parent exposed only the generic socket timeout, and the service's pre-socket stderr was not retained in `supervisor.log`. Whether the correct collected invocation has a queryable journal entry remains pending because the first query used a truncated invocation ID.

This leaves two release-blocking questions:

1. why the deployed supervisor exited before socket readiness; and
2. why the detached launcher did not retain the actionable startup error independently of journal availability.

## Investigation

1. Preserve and inspect the failed state directory, especially file metadata plus any `composition_runtime_{provisioned,ready,failed}` events. Do not read or publish helper credential material.
2. Compare direct local `pi` startup on Rose with the SSH-backed `pi --ssh rose.dos:/scratch/theo/qshell-project` path. Both supported paths must either work with the lease runtime or fail immediately with a typed, durable reason.
3. Determine whether failure occurred before exec, while reading the protected `EnvironmentFile`, while loading the helper credential/bootstrap metadata, during composition-runtime preflight, or during `server.New`.
4. Preserve service stderr independently of journald and `--collect`. A pre-socket service failure must be returned or copied into the mode-0600 session log before cleanup.
5. Add a deterministic delegated-systemd test in which the supervisor exits before creating the socket and no journal is available; assert that the caller reports the real failure rather than only a timeout.
6. Extend the packaged downstream gate to exercise the same Pi local-launch lifecycle and Rose XDG/state topology, not only the lower-level unprivileged supervisor service.

## Security and rollout constraints

- Do not retry by weakening Landlock, seccomp, `no_new_privs`, strict eBPF enforcement, command policy, or project-overlay boundaries.
- Do not grant project policy access to `/run/agentsh/nethelper`, helper credentials, bootstrap metadata, or composition runtime paths.
- Do not reuse or remove `/agentsh-composition-scratch` until the fresh lease-runtime session passes and the known-good reference is deliberately retired.
- Do not run recursive cleanup against the failed lease or state tree; preserve evidence and use authenticated lifecycle release only after the failure is understood.
- Do not run `vivado -version`, hardware programming, reset, driver, fleet, KVM, or microVM operations while startup is blocked.

## Related issues

- `issues/composition-runtime-productionization.md`
- `issues/qshell-bubblewrap-composition-live-rollout-gaps.md`
- downstream `nix-config/issues/agentsh-trusted-fhs-sandbox-composition.md`
