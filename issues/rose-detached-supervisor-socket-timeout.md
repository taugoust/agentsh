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

After the 15-second wait failed, the transient `--collect` unit no longer existed and `systemctl --user status` reported that the unit could not be found. The corrected invocation query showed that the service reached `server.New` and then logged `composition runtime preflight: composition runtime has unsafe type, mode, or ownership`. The mode-0600 `events.jsonl` durably contains the matching `composition_runtime_failed` event. The initial diagnostic command had accidentally omitted the invocation ID's final `f`; that empty query was not evidence of missing journal retention.

## Preserved Rose evidence

Direct read-only inspection of the retained lease proves that the inode metadata was valid and unchanged before the failed preflight:

- lease directory: raw mode `040711`, `root:root`, displayed mode `0711`;
- composition child: raw mode `041733`, `root:root`, displayed mode `1733`;
- filesystem: host `/run` tmpfs;
- composition birth/change time: `2026-07-23 16:56:11.904252675 +0000`;
- failed preflight: `2026-07-23 16:56:12.250727 +0000`.

Python `lstat` independently reported directory type `040000`, permissions `01733`, sticky bit set, no set-ID bits, UID `0`, and GID `0`. An equivalent transient `systemd-run --user` probe saw the same values and an identity UID/GID map (`0 0 4294967295`). No matching user-unit drop-in exists. This rules out user-namespace remapping, post-failure chmod repair, a non-tmpfs runtime, and unit-name hardening overrides.

## Expected behavior

A schema-3 helper lease should provide the authenticated `composition_scratch_root`, the delegated user supervisor should persist `composition_runtime_provisioned` and `composition_runtime_ready`, and `agentsh session start --detach` should return the session ID and supervisor socket. A fresh Pi session should then run the harmless `nix develop .#ultrascale --command true` canary before any `vivado -version` invocation.

## Actual behavior

`systemd-run --user` accepted the transient service, but AgentSH's `os.FileInfo`-based predicate rejected an inode whose raw Linux stat metadata exactly matched the required topology. The process exited before creating `supervisor.sock`; the parent exposed only the generic socket timeout, and `supervisor.log` retained only the `systemd-run` launch line. The actionable preflight error was available only after querying the corrected invocation ID in the user journal.

The correction must both validate provisioning/admission through one raw Linux inode predicate and retain the actionable startup error independently of journal availability. Live Rose acceptance remains the release blocker.

## Candidate correction

The candidate replaces both duplicated `os.FileInfo` checks with one `unix.Lstat`/raw-mode predicate shared by privileged provisioning and supervisor admission. It requires exact directory type, mode `01733`, UID/GID `0:0`, and rejects set-ID bits. Failure strings now include the observed type, mode, UID, and GID, so the mandatory durable event is actionable. Detached systemd launches additionally set `StandardOutput=append:` and `StandardError=append:` to the existing mode-0600 session log, preserving pre-socket failures independently of journald and `--collect`.

Focused formatting/unit checks pass, including exact metadata acceptance; type, sticky-bit, permissions, set-ID, UID, and GID rejection; and both private log-routing properties. The final complete AgentSH and downstream flakes pass (`/tmp/agentsh-rose-runtime-full-flake-check-final.log` and `/tmp/agentsh-rose-runtime-downstream-full-check-final.log`). The downstream automatic-runtime gate passes at `/nix/store/hkp07618c02wdzaz6kjqsnjch3sa9anp-vm-test-run-agentsh-qshell-composition-release-gate` before this evidence-only update; its malformed-mode case asserts durable detail `type=040000 mode=0733 uid=0 gid=0`. A fresh Rose local-launch canary remains required before resolution.

## Remaining acceptance and follow-up

1. Compare direct local `pi` startup on Rose with the SSH-backed `pi --ssh rose.dos:/scratch/theo/qshell-project` path after deploying the corrected predicate. Both supported paths must either work with the lease runtime or fail immediately with a typed, durable reason.
2. Add an end-to-end delegated-systemd test in which the supervisor exits before creating the socket and no journal is available; the command-construction regression already requires private stdout/stderr routing.
3. Extend the packaged downstream gate to exercise the same Pi local-launch lifecycle and Rose XDG/state topology, not only the lower-level unprivileged supervisor service.

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
