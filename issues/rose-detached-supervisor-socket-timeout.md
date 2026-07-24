# Rose detached supervisor exits before publishing its socket

## Status

Open release blocker. The first fresh Rose launch after deploying AgentSH `39aaacb4e52ab27338291162ce2da5c1be080531` through `nix-config` `a32d1b4` timed out before the detached supervisor published its Unix socket. AgentSH `01a4627f43533d52f5617abb9e7756343263cb04` and `nix-config` `6d2f24e` added raw metadata diagnostics and private pre-socket logging, but the first generation-37 retry then proved that Rose intentionally reports host `root:root` as overflow UID/GID inside the actual delegated service. Do not continue to the QShell or Vivado canary until the authenticated ownership correction is deployed and a fresh harmless canary passes.

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

Python `lstat` independently reported directory type `040000`, permissions `01733`, sticky bit set, no set-ID bits, UID `0`, and GID `0`. A simple transient `systemd-run --user` probe without the production launcher's private mount setup saw an identity UID/GID map, but that probe did not reproduce the actual service namespace. Read-only inspection of running AgentSH transient services later showed the production shape exactly: UID map `2016 2016 1` and GID map `100 100 1`. In that namespace host root is intentionally unmapped. The host evidence still rules out post-failure chmod repair, a non-tmpfs runtime, and unit-name hardening overrides; it does not rule out ownership translation.

After generation 37 activated `01a4627f`, fresh session `session-7c58a717-3b03-4c0e-98f3-196d1f779f75` ran `/nix/store/ygw3vfy49ansxxzxjbhz5h3540wf2x2z-agentsh-unstable-2026-06-17/bin/agentsh`. Its mode-0600 `logs/supervisor.log` independently retained the actionable failure:

```text
composition runtime preflight: composition runtime has unsafe type, mode, or ownership (type=040000 mode=01733 uid=65534 gid=65534; expected type=040000 mode=01733 uid=0 gid=0)
```

The matching durable `composition_runtime_failed` event contains the same fields. This confirms that raw `stat` was correct and that accepting overflow IDs as root would be ambiguous and unsafe: any host owner omitted from the narrow map appears as the same overflow identity.

## Expected behavior

A schema-3 helper lease should provide the authenticated `composition_scratch_root`, the delegated user supervisor should persist `composition_runtime_provisioned` and `composition_runtime_ready`, and `agentsh session start --detach` should return the session ID and supervisor socket. A fresh Pi session should then run the harmless `nix develop .#ultrascale --command true` canary before any `vivado -version` invocation.

## Actual behavior

`systemd-run --user` accepted both transient services. The original `os.FileInfo` predicate hid the observed fields; the raw-stat correction then showed that the exact supervisor context sees the valid host-root inode as `65534:65534`. The first process exposed only the generic timeout and required the corrected journal invocation ID for diagnosis. The second process also exited before creating `supervisor.sock`, but its private log and durable event retained the complete error independently of journald.

Local mode and overflow ownership are insufficient to prove host ownership. Admission must authenticate a privileged helper observation of the fixed lease path and prove that it names the same device/inode/type/mode observed by the unprivileged supervisor. Live Rose acceptance remains the release blocker.

## Candidate correction

The follow-up adds the authenticated, read-only `attest_composition_runtime` helper operation. Its request carries only the fixed lease ID and in-memory helper credential; it accepts no caller-selected path. The privileged helper derives the schema-3 composition child and lease parent, rejects symlinks, and applies the shared raw Linux type/mode/host-UID/host-GID predicates. It returns device/inode/mode identities for those two fixed objects. The unprivileged supervisor independently resolves and stats the same paths, validates the attested host ownership as `root:root`, and requires exact device/inode/mode equality. It never treats UID/GID `65534` as root.

The same attestation is required during helper rebinding. Provisioning now applies the shared raw predicate to the immutable root-owned lease parent as well as the sticky mode-`1733` composition child. The operation is credential- and peer-authenticated, advertised as an instance lifecycle capability, and fails closed if an older helper does not implement it. Existing detailed failures and private `StandardOutput=append:`/`StandardError=append:` routing remain intact.

Nix-native unit, formatting, lifecycle, and complete AgentSH flake checks pass (`/tmp/agentsh-root-attestation-go-unit-tests.log`, `/tmp/agentsh-root-attestation-go-format.log`, `/tmp/agentsh-root-attestation-nethelper-lifecycle-tests.log`, and `/tmp/agentsh-root-attestation-full-flake-check.log`). The downstream automatic-runtime VM now runs its main supervisor with only UID/GID `1234` mapped and host root absent, reproducing Rose's ownership view. It passes startup and readiness, malformed-mode refusal with durable host metadata, all seven QShell plans, six command-correlated cleanups, zero approvals, empty pools, and authenticated lease teardown at `/nix/store/d8rw5c3rc6i7n2i8rdpv3973dv4gcgql-vm-test-run-agentsh-qshell-composition-release-gate`; log `/tmp/agentsh-root-attestation-qshell-release-gate.log`. A fresh Rose local-launch canary remains required before resolution.

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
