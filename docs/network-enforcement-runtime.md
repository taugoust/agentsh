# Detached network runtime evidence and NixOS helper deployment

Detached network reporting is evidence-based. Policy decisions and launch flags are not enforcement evidence.

## Runtime object

Detached metadata, `GET /api/v1/sessions/<id>`, `GET /api/v1/sessions/<id>/network-enforcement`, the central detached-supervisor API, session-start JSON, and network `debug policy-test` output expose `network_enforcement`.

Important fields:

- `requested`: `none`, `best-effort`, or `strict` (`ebpf.required`/`ebpf.enforce`).
- `readiness`: session-start result (`none`, `degraded`, `ready`, or `failed`). It does not become `active` for a command.
- `status`: current state: `none`, `degraded`, `ready`, per-command `active`, or `failed` after a refusal/cleanup failure.
- `tier`: the observed mechanism. `helper-ebpf-proxy-required` means commands may reach only exact AgentSH TCP proxy endpoints after a successful attachment; it does not mean transparent redirect.
- `preflight`: session-start evidence for disposable cgroup placement, helper attach/map/cleanup, proxy readiness, the tool boundary, local direct-bypass/unsupported-traffic probes, and the fail-closed barrier.
- `attachment`: per-command helper registration, cgroup, locked initial/default-deny map, exact proxy endpoint, blocked traffic classes, and pin/reload evidence. It contains no credential.
- prerequisite booleans: cgroup delegation, helper authentication, proxy readiness, tool-boundary activation, direct-bypass blocking, unsupported-traffic blocking, and fail-closed setup.

`network_policy_enforced` is recomputed at serialization time. It cannot be true unless readiness is `ready`, the disposable preflight proves every prerequisite, the report is `ready` or has a proven `active` attachment at the proxy-required tier, exact TCP-proxy-only/default-deny behavior is present, unsupported traffic (including raw sockets) is denied, and fail-closed setup is proven. Old or malformed metadata claiming `true` without those fields is normalized to `false`.

`policy-test` evaluates a policy decision only. Its runtime object includes `operation_executed=false`; it must not be interpreted as an attachment test.

The central `/api/v1/detached-supervisors` endpoint prefers the live supervisor object and marks it with `network_enforcement_source=supervisor-runtime` and `network_enforcement_live=true`. If that query fails, metadata is labeled `metadata-snapshot-stale`, forced to non-ready evidence (`degraded`, `failed`, or `none`), and can never preserve an enforced claim.

At session start the launcher calls `POST /api/v1/sessions/<id>/network-enforcement/preflight` after session/proxy creation. Strict detached startup refuses any response other than proven `ready` and records `readiness=failed,status=failed` metadata before stopping the supervisor. Non-strict sessions may continue with an explicit degraded warning. `GET /api/v1/sessions/<id>/network-enforcement` refreshes passive evidence; the session API also embeds the same object.

The preflight is disposable and active. It first requires the observed cgroup root to be the delegated `agentsh-supervisor-*.service` transient unit; a direct/home-manager launch remains degraded even if it carries lookalike environment settings. It then starts a stopped child with an intentionally failing setup hook and verifies that its first-instruction marker is never created. Next it starts the installed strict wrapper/jail through the normal command runner and cgroup hook. Before resume the supervisor verifies the marker is still absent, observes the child PID in the new command cgroup, and captures the helper's authenticated registration, fixed-program attachment, locked initial/default-deny map, exact proxy entries, pin state, and one-way registration evidence ID. Inside the jail the probe verifies the private proc view, hidden cgroupfs/helper/credential and supervisor-control paths, reserved-environment scrubbing, descriptor closure, `no_new_privs`, and empty inheritable/permitted/effective/bounding/ambient capability sets. It connects to the exact proxy listener, attempts a different local TCP listener, attempts local UDP, and attempts IPv4, IPv6, and packet raw sockets. TCP/UDP blocking counts only when the connect/send syscall returns a gate permission denial; a timeout, reset, missing UDP reply, or merely empty listener is not gate evidence. The supervisor independently verifies that the non-proxy TCP listener accepted nothing and the UDP listener received nothing. Finally, helper and cgroup cleanup must succeed.

No public address or DNS lookup is used by preflight. A missing synchronous approval manager, missing wrapper, failed namespace/mount operation, in-process (non-helper) BPF fallback, unpinned helper attachment, map mismatch, reachable local bypass listener, unsupported traffic success, or cleanup error leaves best-effort sessions visibly degraded and causes strict detached startup to be refused. The proxy converts unresolved approval decisions, missing approval infrastructure, denial, timeout, cancellation, malformed targets, DNS failure, and dial errors to fail-closed outcomes; it performs no destination DNS lookup or upstream dial before the network approval resolves.

## NixOS root helper

The NixOS module can install one root helper/socket per configured Unix UID:

```nix
users.users.alice.uid = 1000;

services.agentsh = {
  enable = true;
  nethelper = {
    enable = true;
    instances.alice = {
      user = "alice";
      uid = 1000;
      # Runtime secret supplied by sops-nix/agenix/systemd credentials.
      # Never use a Nix store path. Use at least 32 bytes of random,
      # whitespace-free secret material.
      credentialFile = "/run/secrets/agentsh-nethelper-alice";
    };
  };
};
```

For UID 1000 the defaults are:

- root helper: `agentsh-nethelper-alice.service`;
- socket: `/run/agentsh/nethelper/1000/nethelper.sock`, mode `0600`, owned by `alice`;
- launcher credential copy: `/run/agentsh/nethelper/1000/instance-credential`, mode `0400`, owned by `alice`;
- pins: `/sys/fs/bpf/agentsh/nethelper/1000/`;
- detached supervisors: transient user services with `Delegate=yes`.

The helper remains root, verifies `SO_PEERCRED` against the configured UID, requires the instance credential, validates real cgroup containment, and accepts only fixed AgentSH helper operations. Its service is capability-bounded and restricted to AF_UNIX, its protected runtime/credential source, cgroup inspection, and its bpffs subtree.

A generated profile fragment selects the instance by numeric UID, exports only the socket and credential-file paths, and opts detached supervisors into delegated `systemd-run --user` startup. Literal helper credentials are never copied into `systemd-run` arguments or transient-unit environment properties. The detached event token and non-secret helper path assignments are passed through a mode-`0600` transient `EnvironmentFile`, not command-line `--setenv`; the launcher removes that file as soon as the supervisor has execed and before session/preflight commands start. The supervisor reads the UID-owned mode-`0400` helper runtime copy before opening its API, validates it, captures the value in the trusted `App`, and removes the value, legacy alias, and source path from its environment. Session-start JSON and discovery output omit the detached event token. A new login shell is required after deployment.

The transient user service uses `Delegate=yes`, a private temporary directory/keyring, `NoNewPrivileges`, a private umask, and no core dumps. Direct launch and a missing user manager remain explicit degraded fallbacks; they are not cgroup evidence.

## Safety boundary and deployment acceptance

The strict Linux wrapper establishes a user/mount/PID/cgroup command jail, private proc, hidden cgroupfs/control paths, reserved-environment scrubbing, capability drops, and `no_new_privs`, all behind the stopped-child setup barrier. `tool_boundary_active`, unsupported-traffic fields, and `network_policy_enforced` remain false unless the disposable probe observes those properties on the running host. A normal command can become `active` and enforced only when that ready preflight is still present and its own authenticated, pinned, exact-proxy attachment succeeds before resume. On exit the report returns to session-scoped `ready`; any setup or cleanup failure becomes visibly `failed` and emits command-scoped evidence.

Deployment still owns the host acceptance checks below. Service configuration alone never bypasses preflight or upgrades a degraded report.

- Verify the installed NixOS helper capabilities, socket/runtime ownership, bpffs mount, and systemd hardening on the target kernel.
- Run the local HTTPS/proxy approval scenario and confirm no upstream request occurs before approval; verify both deny and approve resolutions.
- Kill/restart the helper and supervisor at controlled points and confirm pinned default-deny state has no allow window.
- Run the full same-UID adversarial suite (helper guessing, proc/fd access, cgroup movement, signals/ptrace, credential rotation) from the deployed tool identity.
- Exercise local and SSH/user-manager detached startup and the NixOS VM regression matching the original pi-auto reproduction.
