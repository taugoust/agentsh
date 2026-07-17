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

The preflight is disposable and active. It first requires the observed cgroup root to be the delegated `agentsh-supervisor-*.service` transient unit; a direct supervisor launch (including Home Manager use without an active SSH-bootstrap lease) remains degraded even if it carries lookalike environment settings. It then starts a stopped child with an intentionally failing setup hook and verifies that its first-instruction marker is never created. Next it starts the installed strict wrapper/jail through the normal command runner and cgroup hook. Before resume the supervisor verifies the marker is still absent, observes the child PID in the new command cgroup, and captures the helper's authenticated registration, fixed-program attachment, locked initial/default-deny map, exact proxy entries, pin state, and one-way registration evidence ID. Inside the jail the probe verifies the private proc view, hidden cgroupfs/helper/credential and supervisor-control paths, reserved-environment scrubbing, descriptor closure, `no_new_privs`, and empty inheritable/permitted/effective/bounding/ambient capability sets. It connects to the exact proxy listener, attempts a different local TCP listener, attempts local UDP, and attempts IPv4, IPv6, and packet raw sockets. TCP/UDP blocking counts only when the connect/send syscall returns a gate permission denial; a timeout, reset, missing UDP reply, or merely empty listener is not gate evidence. The supervisor independently verifies that the non-proxy TCP listener accepted nothing and the UDP listener received nothing. Finally, helper and cgroup cleanup must succeed.

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

## Ephemeral helper for remote Home Manager hosts

A trusted parent `pi --ssh` workflow may create one temporary helper lease when the remote Linux host has AgentSH in an immutable Nix store path and the remote user has sudo, but no persistent helper service. This is an alternative activation lifecycle for the same fixed helper backend and authorization contract, not a weaker enforcement tier.

The wrapper obtains a random lease ID, allocates a remote TTY so sudo owns the password conversation directly, and invokes the root-only bootstrap command before any detached supervisor or tool exists. Bootstrap verifies `SUDO_UID`/`SUDO_GID`, cgroup v2, bpffs, systemd, fixed runtime paths, and the immutable AgentSH launcher. It creates only a protected `/run/agentsh/nethelper/<uid>/<lease>/` subtree, a matching bpffs lease subtree, a random root source credential, and the UID-owned runtime copy. The credential value never appears in argv, output, logs, metadata, or the bootstrap result.

Bootstrap launches a collected transient root systemd service with the persistent helper's BPF/network capabilities and hardening. `CAP_CHOWN` is available only while the root service gives its mode-`0600` Unix socket to the target UID; the process immediately removes it from its effective, permitted, and inheritable capability sets before serving. The service accepts only the fixed helper operations. It does not install files under `/etc`, create a root profile, or persist across reboot.

The bootstrap runtime contract is bounded and machine-readable:

```console
agentsh nethelper capabilities --json
sudo agentsh nethelper bootstrap --uid "$uid" --gid "$gid" --lease "$lease" --runtime 192h
# Only renewal-capable wrappers opt in:
sudo agentsh nethelper bootstrap --uid "$uid" --gid "$gid" --lease "$lease" --runtime 192h --soft-lease 49h
```

`--runtime` defaults to `13h` for old wrappers, must be a positive whole-second Go duration, and cannot exceed `192h`. Bootstrap schema 2 adds `started_at`, `expires_at`, `runtime_seconds`, and `bootstrap_schema_version` while retaining helper protocol version 1. `RuntimeMaxSec` and `expires_at` derive from the same start instant and duration. Capability JSON advertises `bootstrap_runtime`, `bootstrap_default_runtime_seconds`, `bootstrap_max_runtime_seconds`, and `instance_lifecycle`.

Soft expiry is negotiated, never implicit. Legacy and `--runtime`-only callers set no soft lease and live until hard expiry. A renewal-capable wrapper commits with `--soft-lease 49h`; bootstrap records `soft_lease_seconds` and `renewal_required`, and the serve process receives the same duration. The authenticated renewable soft lease remains independently bounded by hard expiry. Wrapper-owned lifecycle commands are:

```console
agentsh nethelper status --socket "$socket" --credential-file "$credential_file" --lease "$lease" --json
agentsh nethelper renew  --socket "$socket" --credential-file "$credential_file" --lease "$lease" --json
```

The corresponding protocol-v1 operations are `instance_status` and `renew_instance`. Their responses contain only helper kind, lease/unit identity, capabilities, creation/soft/hard expiry, active registration count, status/reason, and renewal generation. They authenticate the Unix peer UID/GID, lease, and instance credential; the credential is never returned. Renewal never moves the soft deadline beyond the finite hard deadline. Soft expiry stops the service, and release remains forbidden while registrations are active.

The trusted wrapper passes only the lease socket and credential-file paths to a delegated transient **user** supervisor. Strict startup still requires the same disposable helper/proxy/command-jail/bypass preflight and reports the same `helper-ebpf-proxy-required` tier. The helper supports all commands and subagents in that one top-level remote Pi session; concurrent Pi invocations receive separate leases.

Normal shutdown stops the detached session first, then sends the fixed authenticated `release_instance` operation. Release is refused while any command registration remains. After successful release, the helper removes maps/links, credential files, socket, and runtime state and exits so systemd collects the unit. On crashes or expiry, populated/live cgroups retain pinned default-deny links; stale reaping removes only validated pins whose owner is dead and whose cgroup is gone or unpopulated. There is no unrestricted fallback when sudo, bootstrap, delegation, or preflight fails.

The wrapper creates a random token at the fixed `agentsh-wrapper-control/nethelper-recovery.token` topology; the wrapper-owned control directory is mode `0700` and the file is mode `0600`. It exports only that path as `AGENTSH_NETHELPER_RECOVERY_TOKEN_FILE` to the supervisor and retains the file for its own recovery client. The supervisor validates and retains the canonical path, reads the token once, unsets the variable, and includes the entire token container in every strict command-jail control-path mount hide. Wrapper control environment is scrubbed and non-stdio descriptors are closed before the command body runs. The token and path are never included in lifecycle metadata, command environment, output, or logs.

The supervisor captures helper paths and credentials once at startup and removes the raw helper environment variables. Initial launch accepts `AGENTSH_NETHELPER_SOCKET`, `AGENTSH_NETHELPER_CREDENTIAL_FILE`, and optional `AGENTSH_NETHELPER_BOOTSTRAP_RESULT` (the protected `bootstrap.json` path); when the latter is absent it is derived beside the socket for backward compatibility. Live `network_enforcement.helper_lifecycle` evidence contains no secrets and reports authenticated status, soft/hard remaining seconds, socket/credential-source liveness, active registrations, and binding/renewal generations. A failed authenticated status check immediately makes strict evidence sticky `failed`; recreating a socket path cannot restore readiness.

A wrapper may transactionally bind a replacement helper to the **same** session:

```console
agentsh session nethelper-rebind "$session_id" \
  --bootstrap-result "$bootstrap_json" \
  --socket "$socket" \
  --credential-file "$credential_file" \
  --expected-lease "$lease" \
  --expected-generation "$generation" \
  --recovery-token-file "$wrapper_recovery_token_file"
```

This invokes:

```text
POST /api/v1/sessions/{id}/network-enforcement/helper/rebind
Content-Type: application/json

{
  "bootstrap_result_path": "/run/agentsh/nethelper/<uid>/<lease>/bootstrap.json",
  "socket_path": "/run/agentsh/nethelper/<uid>/<lease>/nethelper.sock",
  "credential_file": "/run/agentsh/nethelper/<uid>/<lease>/instance-credential",
  "expected_lease_id": "lease-...",
  "expected_binding_generation": 1
}
```

The CLI sends the token only in `X-AgentSH-Nethelper-Recovery` over the configured private supervisor Unix socket. The route rejects TCP requests, generic API/session credentials, auth-disabled callers, missing tokens, and wrong tokens.

The endpoint requires the detached supervisor to contain exactly one session, serializes session topology and execution, generation-checks, validates fixed protected paths and schema-2 metadata, reads the candidate credential only into memory, authenticates candidate status, rejects active/uncertain registrations, and stages the candidate for the complete strict disposable preflight. It commits and increments generation only when the report is proven ready. Otherwise it records an independent candidate cleanup tombstone containing lease/helper identity and all observed registration/cgroup/pin evidence before restoring the old binding. When registration identity was observed, rebind, release/teardown, and hard-expiry reaping remain refused until an exact authenticated cleanup RPC succeeds and authenticated candidate status then reports active state with zero registrations; a zero count alone cannot erase the tombstone. It never creates or substitutes a session ID and never releases the old helper before commit.

## Safety boundary and deployment acceptance

The strict Linux wrapper establishes a user/mount/PID/cgroup command jail, private proc, hidden cgroupfs/control paths, reserved-environment scrubbing, capability drops, and `no_new_privs`, all behind the stopped-child setup barrier. `tool_boundary_active`, unsupported-traffic fields, and `network_policy_enforced` remain false unless the disposable probe observes those properties on the running host. A normal command can become `active` and enforced only when that ready preflight is still present and its own authenticated, pinned, exact-proxy attachment succeeds before resume. On exit the report returns to session-scoped `ready`; any setup or cleanup failure becomes visibly `failed` and emits command-scoped evidence.

Execution responses add `result.outcome` with `command_started`, `dispatch_state`, `failure_kind`, `retryable`, semantic `code`/`message`, and queue/execution durations. `tools/exec_bash` promotes that object plus `command_started`, `error`, `error_code`, and `error_message` to its top-level result while retaining `exec_response`. A pre-exec/helper refusal has `command_started=false`; a genuine child `exit 127` has `command_started=true`, `failure_kind=child_exit`, and no infrastructure error. Context-aware execution admission prevents a cancelled queued REST/tool command from acquiring the session slot later.

Deployment still owns the host acceptance checks below. Service configuration alone never bypasses preflight or upgrades a degraded report.

- Verify the installed NixOS helper capabilities, socket/runtime ownership, bpffs mount, and systemd hardening on the target kernel.
- Run the local HTTPS/proxy approval scenario and confirm no upstream request occurs before approval; verify both deny and approve resolutions.
- Kill/restart the helper and supervisor at controlled points and confirm pinned default-deny state has no allow window.
- Run the full same-UID adversarial suite (helper guessing, proc/fd access, cgroup movement, signals/ptrace, credential rotation) from the deployed tool identity.
- Exercise local and SSH/user-manager detached startup and the NixOS VM regression matching the original pi-auto reproduction.
