# pi-auto network policy approval is not enforced at runtime

## Status
Open for clearer early-exit diagnostics, the remaining rollout/recovery pilots, and the concrete consistency/recovery follow-ups below. Strict local sessions work with persistent helpers on `matebook` and `virby-vm`; local Home Manager-only Linux and remote `pi --ssh`/`pi-auto --ssh` can create bounded ephemeral helpers, and the user has confirmed both the remote path against `graham` and plain local Pi startup.

## Deployment status (updated 2026-07-13)

### `matebook` local — working

The installed NixOS topology now uses the per-UID root nethelper, a delegated transient user supervisor, the strict command jail, and the proxy-required eBPF gate. A fresh normal `pi` session reports live strict network evidence and the user has observed prompts for unknown network destinations.

Deployed revisions:

- AgentSH `90f6adcba9f024d7f85551ee4f471539493b64ed`;
- `pi-agent-extensions` `1df2e40ff94319180321262d31143c8cea2a3c6e`;
- `nix-config` `b748ae4` (`Add proper network sandboxing`).

The earlier detached attach-only/resource-limit mismatch was fixed by not requesting CPU, memory, or PID controllers that this topology cannot enforce; command, idle, and session timeouts remain active. Detached subagent runtime settings now also cross the transient-systemd boundary.

This proves that the Matebook-local deployment reaches the live approval UI.

### `virby-vm` — working

The original Virby failure happened before socket creation: strict eBPF was configured, but the VM had no per-UID nethelper or delegated transient-supervisor environment. The unprivileged supervisor exited its capability check immediately, while the launcher only surfaced a socket timeout.

`nix-config` commit `22e79f6` (`fix(virby): deploy strict network helper`) added the UID 501 helper/socket, encrypted runtime credential provisioning, user lingering/delegation, the generated helper profile, and removal of native parent-Pi `fetch`. After rebuilding, the user confirmed that normal `pi` startup works.

Two post-deployment sessions independently recorded strict live evidence:

- `session-39ed0ff8-f9d8-4261-8b49-85446caa2907`;
- `session-defeeccf-7721-4742-93a9-3042ffbce9d6`.

Both report `requested/readiness/status = strict/ready/ready`, tier `helper-ebpf-proxy-required`, and `network_policy_enforced = true`. Their active preflights prove delegated attach-only cgroups, authenticated helper attachment, pinned and locked default-deny maps, exact proxy-only access, command-jail isolation, blocked direct TCP/UDP/QUIC/raw sockets, the fail-closed barrier, and cleanup.

### Strict startup warning — resolved

AgentSH `926af140` removes the successful-path migration warning from `detachedSupervisorNetworkEnforcementWarning`. Strict intent is now quiet; degraded best-effort behavior and real launch/preflight failures retain diagnostics. This does not force `network_policy_enforced=true` or weaken the disposable active preflight.

### TUM DOS Home Manager hosts — remote SSH path working

The persistent installer design was replaced with one lease-scoped helper per top-level remote Pi lifecycle. AgentSH `926af140` provides root-only `nethelper bootstrap`, authenticated `release`, transient systemd hardening, fixed per-UID/per-lease runtime and bpffs paths, setup-only `CAP_CHOWN`, expiry, and conservative stale-state reaping. The full strict lifecycle passed the privileged Virby smoke, including the delegated supervisor and disposable BPF/proxy/command-jail/bypass/cleanup preflight.

`nix-config` `8bad828` enables strict DOS cgroup/network/eBPF intent and wires a shared trusted-parent bootstrap into both `pi --ssh` and `pi-auto --ssh`. Sudo runs through an allocated remote TTY before the sandbox exists, so Pi/AgentSH never capture the password. No `/etc` unit, root profile, Home Manager sudo activation, persistent credential, or fleet-wide root installation is created. `pi-auto --ssh` retains its bounded helper and a dedicated SSH control connection through shadow review/resume and releases them after accept/reject. Missing bootstrap, helper, delegation, or preflight aborts rather than falling back.

The user reports that the deployed `--ssh` path works against the x86_64 DOS host `graham`. Native parent-Pi `fetch` was also removed from the last macOS supervised bundle in `nix-config` `a2fa3db`; `pi-agent-extensions` `b0b2c24` independently refuses to register it in any supervised session.

### Direct local invocation — working

The original direct invocation on `graham` failed closed before socket creation because local mode did not bootstrap a helper:

```text
ssh graham ~/Workspace/nix-config ❯ pi
timed out waiting for supervisor socket /scratch/theo/.local/share/agentsh/sessions/session-d56cbd6c-4730-4ae5-a9ef-4d5ce68229bf/supervisor.sock
```

The `nix-config` commit `Fix direct usage with pi --ssh` adds a generic local Linux lifecycle to the shared trusted-parent library and wires it into both `pi` and `pi-auto`. It validates and silently reuses a protected persistent per-UID helper when available. Otherwise it invokes terminal-connected sudo before session/sandbox creation, validates the immutable AgentSH bootstrap result, passes only the socket and credential-file paths to the delegated supervisor, and removes those controls from the parent Pi environment. Plain `pi` stops the session and releases an ephemeral helper on exit. Local `pi-auto` records only non-secret lease metadata, retains the helper through shadow review/resume, and releases it after accept/reject; mutating fallback is refused while a managed helper session remains.

The first Virby test correctly fell back to an ephemeral helper and exposed a separate persistent provisioning bug: a NixOS switch restarted `agentsh-nethelper-taugoust.socket` and its helper service, but the `RemainAfterExit` provisioning oneshot stayed active and did not recreate the user-readable runtime credential. The AgentSH `fix(nethelper): reprovision credential on socket restart` commit makes provisioning `PartOf` the socket, so every socket stop/restart also stops/reruns provisioning before the socket listens. After rebuilding, the provision service and socket entered together, the protected credential returned with UID/GID `501:0` and mode `0400`, the socket had `501:0` and mode `0600`, and the user confirmed plain Pi startup works while reusing the persistent helper.

Failures remain fail-closed. The launcher should still surface a transient supervisor's real early-exit/unit diagnostic instead of only timing out on `supervisor.sock`.

## Remaining work

- [x] Remove the obsolete successful strict-startup warning without weakening fail-closed diagnostics.
- [x] Implement and validate the no-install ephemeral helper primitive and remote `pi --ssh`/`pi-auto --ssh` wiring.
- [x] Confirm the remote SSH path on the x86_64 DOS host `graham`.
- [x] Add the trusted direct-local ephemeral bootstrap to Linux `pi` and `pi-auto`, while reusing healthy persistent helpers.
- [ ] Replace the generic supervisor-socket timeout with the underlying early-exit diagnostic.
- [ ] Pilot on an AArch64 DOS host and finish explicit SSH-loss/helper-crash/expiry recovery checks before broader rollout.
- [ ] Reconcile the top-level and nested session network-enforcement reports.
- [ ] Replace fragile SSH argv reconstruction with an encoded or stdin-delimited remote invocation.
- [ ] Reuse the exact immutable AgentSH binary selected during helper probing for remote session/review/cleanup commands.
- [ ] Add an explicit `pi-auto` helper-cleanup recovery operation after a finalized accept/reject.
- [ ] Allow authenticated `pi-auto` recovery when its local SSH control socket is lost but the remote lease remains live.
- [ ] Set transparent-network intent to false everywhere until transparent redirect is implemented and proven.

## Additional concrete follow-up findings

### 1. Conflicting enforcement snapshots

Strict session-start output can report the authoritative top-level `network_enforcement` as `ready` with `network_policy_enforced=true` while the embedded `session.network_enforcement` still contains its initial `degraded`/`false` snapshot. This was visible in the successful ephemeral-helper smoke. Clients that read the nested object can therefore reject a genuinely ready session or report contradictory state. Session serialization should publish one refreshed evidence object, or clearly version/name the initial snapshot so it cannot be mistaken for current evidence.

### 2. Fragile remote argument transport

The `pi-supervised` and `pi-auto` wrappers currently use the equivalent of `ssh host sh -s -- "$@"`. OpenSSH reconstructs those arguments as a remote shell command rather than preserving the local argv boundary. Workspace paths containing whitespace or shell metacharacters can be split or interpreted before the stdin script starts. Helper paths happen to be fixed and validated, but user-selected project paths are not restricted to shell-safe characters. Send structured data over stdin, use a safely encoded payload, or quote every argument with a transport whose decoding has tests; do not rely on OpenSSH preserving argv.

### 3. Immutable binary selection is not end-to-end

Ephemeral probing validates and records a specific immutable `/nix/store/.../bin/agentsh`, and sudo bootstrap/release use that path. Remote session start, session stop, `pi-auto` review, and some cleanup paths still invoke plain `agentsh` through a later remote `PATH` lookup. A profile switch or path difference can select a different AgentSH revision than the helper protocol peer that was validated. For ephemeral leases, persist and use the exact selected binary for every lifecycle command. Persistent-helper mode should similarly resolve one immutable client path before session creation.

### 4. No recovery operation after finalized review

If remote `pi-auto accept` or `reject` succeeds but authenticated helper release subsequently fails, the wrapper correctly retains fail-closed state and its dedicated SSH login. However, the AgentSH shadow session may already be finalized, so rerunning accept/reject can fail before reaching release. Add an idempotent `pi-auto cleanup`/lease-release path that validates remembered non-secret metadata, confirms the session has no active registrations, stops any surviving supervisor, releases the helper, closes the control connection, and clears local state only after success.

### 5. Lost local SSH control socket blocks recovery

Ephemeral remote `pi-auto` records a short-lived local `/tmp` ControlMaster socket to keep the DOS login/user manager alive through review and resume. A local reboot, `/tmp` cleanup, or master-process loss makes current resume/review fail closed even if the authenticated root helper and remote supervisor are still alive. Add a bounded recovery flow that opens a new dedicated SSH login, validates the remembered helper socket/credential path and lease identity without exposing the credential value, rewrites the local control-path state, and only then permits resume/review. If the remote supervisor is already gone, recovery should release safely rather than create a replacement helper for stale state.

### 6. Transparent-network intent is inconsistent

DOS now correctly sets `transparent.enabled=false`, and live strict evidence reports `transparent_redirect=false`; the secure tier is `helper-ebpf-proxy-required`. Some managed NixOS configuration still requests transparent mode, notably `modules/nixos/agentsh-pi-host.nix` and `hosts/work/mbp/virby-guest/agentsh.nix`, even though the Linux backend does not implement transparent redirect. This creates intent/reporting drift and may accidentally select an unvalidated path when support evolves. Set it to false across deployed configurations until a real redirect implementation has its own acceptance tests and evidence tier.

## Historical implementation log

The entries below are retained as the implementation history from before installed Matebook acceptance. Statements such as “drafted locally” and “still incomplete” describe that earlier snapshot and are superseded by the deployment status above.

Earlier landed and pushed:

- `ae703757 fix(detached): warn on unsupported network enforcement` keeps `pi-auto` usable while warning about detached network enforcement mismatch.
- `b22c4ffb docs(issues): plan detached network enforcement` records the helper/delegated-cgroup/proxy plan.

Drafted locally, not committed yet:

- net-only / attach-only cgroup probe foundation in `internal/limits/*`: when attach-only is permitted, probe child cgroup placement without touching `cgroup.subtree_control`, avoiding the `+cpu`/`+memory` poisoning observed on `matebook`; Nix go-unit check passed for this slice.
- opt-in detached supervisor launcher scaffold for `systemd-run --user --collect -p Delegate=yes` with metadata for the systemd unit; currently gated behind `AGENTSH_DETACHED_SUPERVISOR_SYSTEMD_RUN`, not default-enabled; Nix go-unit check passed after this slice.
- helper protocol/client/server skeleton in `internal/nethelper`: strict JSON validation, no bytecode/fd fields, Unix-socket client/server, SO_PEERCRED capture on Linux, fail-closed default authorizer, and supervisor client plumbing.
- helper authorization now checks SO_PEERCRED PID/UID/GID, the per-user helper-instance credential, PID/start-time plus pidfd identity where available, registered command cgroup path/ID ownership, kernel-backed `/proc/<pid>/cgroup`, and real cgroupfs containment under the supervisor delegated subtree; lexical containment remains only for controlled tests.
- hidden `agentsh nethelper serve --socket ...` now requires the installed root service, named systemd credential, and socket activation; its Linux `KernelBackend` loads only AgentSH's embedded cgroup connect/sendmsg programs, attaches helper-owned links, updates helper-owned allow/deny/default-deny maps, pins maps/links under the protected bpffs subtree, and reaps registered/orphaned resources only when ownership is proven.
- detached strict-network behavior now preserves `ebpf.required`/`ebpf.enforce` instead of disabling them; setup failures fail closed, while non-strict/best-effort detached networking still degrades with warnings.
- supervisor command cgroup setup can call a configured helper socket (`AGENTSH_NETHELPER_SOCKET`) and update a proxy-only default-deny gate request; helper control env is scrubbed from tool environments, and `systemd-run` launches explicitly pass the helper socket only to the supervisor service.
- detached metadata/reporting distinguishes no enforcement, cgroup-delegated-only, and helper-requested degraded states without setting `network_policy_enforced=true`.
- helper control-plane hardening now includes strict helper socket path checks (absolute path, protected parent, socket type, 0600 mode, expected root ownership), systemd socket activation, named systemd-credential loading, case-insensitive scrubbing of helper env from tool environments, and a hidden `agentsh nethelper cleanup-pins` recovery command.
- helper restart recovery now reloads existing pinned bpffs maps/links on a subsequent authorized register for the same session cgroup, so a restarted helper can update/cleanup surviving pinned enforcement state; malformed/partial pins fail closed and can be removed explicitly with `cleanup-pins`.
- `debug policy-test --op net_connect` now includes a `runtime_enforcement` object (and human output section) with tier/status, proxy path, per-command direct-bypass blocking notes, fail-closed setup status, and transparent-redirect support=false.
- detached reporting now distinguishes `helper-ebpf-gate` degraded from the proxy-required tier and only permits `helper-ebpf-proxy`/`network_policy_enforced=true` after the active supervisor preflight succeeds.

Still incomplete:

- a reviewed AgentSH NixOS module now defines the root helper/socket, per-UID runtime credential copy, bpffs pins, restricted capabilities/service sandbox, and delegated transient user-supervisor launch; the installed same-UID command-jail and adversarial boundary/preflight checks are still unproven, so packaging alone does not permit `network_policy_enforced=true`;
- full same-UID bypass analysis remains open: the helper performs kernel PID/cgroup/subtree checks and stricter socket validation, while detached metadata/API now record requested/readiness/current status, explicit preflight evidence, and per-command attachment evidence; `network_policy_enforced` remains false until socket/fd/credential hiding, raw-socket denial, and proxy bypass controls are proven in the installed service configuration;
- eBPF transparent redirect program is still not implemented; `BuiltinModeCgroupProxyRedirect` is a compileable protocol mode that the Linux backend rejects fail-closed. Current working mode remains proxy-or-block cgroup gate (loopback proxy allowed, direct external connects default-denied when the supervisor supplies a proxy/default-deny map), so non-proxy-aware tools fail closed rather than being transparently redirected;
- restart recovery, stable supervisor identity, deterministic registration reaping, and validated orphan-pin cleanup are implemented locally but remain unverified against helper/supervisor crash timing on the installed target kernel;
- end-to-end detached network regression check remains to be added/run.

## Problem
In a `pi-autonomous` detached/shadow session, AgentSH policy can say that an unknown HTTPS connection requires approval, but the actual command can still connect successfully without any approval prompt or network audit event.

This is concerning because `pi-autonomous` relies on network policy to make unknown destinations approval-gated. If runtime enforcement is missing, subagents and tools can reach non-allowlisted network destinations despite policy-test reporting `approve`.

## Reproduction / evidence
Tested on `matebook` with a fresh temporary detached `pi-autonomous` session.

Policy test against the session-specific supervisor returned the expected approval decision:

```sh
agentsh --server unix://$sock debug policy-test \
  --session "$sid" \
  --op net_connect \
  --path example.com:443
```

Observed:

```text
Operation: net_connect
Path:      example.com:443

Decision:  APPROVE
Rule:      approve-unknown-https
Reason:    Pi wants to connect to: {{.RemoteAddr}}:{{.RemotePort}}
```

Then a real command in the same session connected successfully with no approval:

```sh
agentsh --server "unix://$sock" exec "$sid" \
  --timeout 20s \
  --output json \
  --events all \
  -- nix run nixpkgs#curl -- -sS -o /dev/null -w 'http_code=%{http_code}\n' https://example.com
```

Observed result:

```json
{
  "result": {
    "exit_code": 0,
    "stdout": "http_code=200\n"
  },
  "events": {
    "file_operations": [],
    "network_operations": [],
    "blocked_operations": [],
    "other": [
      { "type": "command_policy", "policy": { "decision": "allow", "effective_decision": "allow", "rule": "allow-nix" } },
      { "type": "command_started" },
      { "type": "command_finished" }
    ]
  }
}
```

Follow-up session logs filtered for network/approval/connect events were empty.

The resolved config on `matebook` appears to require network enforcement:

```json
"Sandbox": {
  "Network": {
    "Enabled": true,
    "Transparent": { "Enabled": true },
    "EBPF": {
      "Enabled": true,
      "Required": true,
      "Enforce": true
    }
  },
  "Cgroups": { "Enabled": true },
  "Seccomp": {
    "Execve": { "Enabled": true },
    "FileMonitor": { "Enabled": true }
  }
}
```

## Why this matters
This undermines `pi-auto` safety and may also hide the real cause of subagent hangs: approvals are expected to be rare in autonomous mode, but if network enforcement is silently absent, policy behavior and runtime behavior diverge.

A user or agent may believe unknown network access is approval-gated, while `curl`/package managers can reach unknown hosts without any approval or audit trail.

## Confirmed root causes

- Detached Stage 1 supervisors explicitly disable cgroups, `sandbox.network`, transparent networking, and eBPF in `internal/cli/supervisor_session.go` (`configureSupervisorMVP`). That made the detached supervisor's runtime behavior diverge from the original host config and from policy-test output.
- A normal user-owned supervisor on `matebook` cannot create/attach child cgroups under its login-session cgroup, and `agentsh detect` reports eBPF unavailable due missing `CAP_BPF`/`CAP_SYS_ADMIN`. Direct detached eBPF enforcement is therefore not available in that context today.
- `internal/api/app.go` `cgroupHook` was gated only on `sandbox.cgroups.enabled`, even though `applyCgroupV2` supports eBPF-only/attach-only operation.
- `runCommandWithResources` and `runCommandWithResourcesStreamingEmit` ignored post-start hook errors in multiple paths, so commands could continue after cgroup/eBPF setup failure even when enforcement should fail closed.

## Fix direction

The immediate compatibility behavior is warning loudly rather than failing startup, because `pi-auto` currently depends on detached supervisors for both local and SSH use.

The real fix is to keep detached/session-local supervisors, but split privileged kernel-network setup into a small helper. Detached supervisors should remain unprivileged and own session lifecycle, policy, approvals, shadow workspace, and Pi/tool execution. The helper should only attach/update/clean network enforcement for cgroups.

Already-landed partial hardening:

- activate `cgroupHook` for eBPF-only configs; and
- propagate post-start hook errors as command failures instead of logging-and-continuing.

## Plan

### 1. Separate cgroup delegation from eBPF privilege

Detached network enforcement needs two different capabilities:

- a writable cgroup subtree for placing Pi/tool processes; and
- privileged eBPF/network setup for enforcing outbound policy.

On `matebook`, `systemd-run --user -p Delegate=yes ...` proved that the first part can work without root: a user service can create child cgroups and move processes into them. eBPF still reports missing `CAP_BPF`/`CAP_SYS_ADMIN`, so the privileged helper is only for the second part.

### 2. Fix net-only cgroup probing

Cgroup network eBPF attach does not need resource controllers (`+cpu`, `+memory`, etc.). AgentSH should not gate network-only enforcement on resource-controller probing.

Observed probe bug on `matebook`:

- attach-only cgroup placement works before enabling controllers;
- AgentSH's probe writes `+cpu`, then `+memory` fails with `EOPNOTSUPP`;
- after `+cpu`, writing to child `cgroup.procs` fails with `EOPNOTSUPP`.

Fix: for net-only / attach-only mode, create a leaf cgroup and attach/move PIDs without touching `cgroup.subtree_control`. Keep scratch-child resource-controller probing only for resource-limit features.

### 3. Launch detached supervisors with user cgroup delegation where available

Prefer starting detached supervisors via the user manager:

```sh
systemd-run --user --collect -p Delegate=yes agentsh supervisor run ...
```

This gives the supervisor a writable delegated subtree while keeping it unprivileged. For strict SSH or direct-local use, handle user-manager availability explicitly (`XDG_RUNTIME_DIR`, the live login/keepalive, and remote user systemd). If delegation is unavailable, strict startup must refuse rather than fall back.

### 4. Add a narrow privileged network helper

Introduce a small helper/service that:

- runs with the minimal required privileges/caps for BPF/network setup;
- loads only AgentSH's fixed, built-in BPF programs;
- never accepts arbitrary BPF bytecode or privileged fds from clients;
- attaches `bpf_link`s to requested cgroups;
- updates allow/deny/redirect maps on supervisor request;
- owns cleanup/reaping; and
- never runs Pi/tools or arbitrary commands.

On managed NixOS machines, install one socket-activated root helper per UID and reuse it without prompting. On Home Manager-only machines with sudo, do not install persistent root state: a trusted outer wrapper creates one fixed, transient, authenticated helper lease per top-level Pi lifecycle before the sandbox starts. Sudo owns the terminal password exchange directly; the unprivileged delegated supervisor and all commands/subagents in that lifecycle share the lease. Concurrent invocations use separate leases. Release is authenticated and refused while registrations remain; expiry/crash paths retain pinned default-deny state until validated cleanup. A missing helper/bootstrap/delegation/preflight always refuses strict startup.

### 5. Protect the helper from same-UID agent tools

Supervisor and Pi/tools run as the same Unix user, so `SO_PEERCRED` UID is not enough. The helper control socket and BPF map fds must be unreachable from agent-controlled processes.

Required boundaries:

- helper authenticates clients with Unix credentials plus PID/cgroup checks and session nonce;
- helper verifies requested target cgroup is inside the caller's delegated subtree;
- supervisor never passes BPF/map/link fds to tools;
- helper socket path/fd is hidden from tools, e.g. via mount namespace/fd hygiene; and
- all helper/control fds are `CLOEXEC`.

### 6. Use proxy-based approval semantics

Pure cgroup eBPF cannot wait for human approval and sees IP:port, not hostname. Full `approve-unknown-https` semantics require a userspace proxy in the path.

Target high-assurance design:

- cgroup eBPF gates/redirects outbound TCP to an AgentSH proxy;
- proxy sees hostname/SNI/HTTP CONNECT metadata;
- proxy evaluates network policy and handles approvals synchronously; and
- direct bypass is denied/fails closed.

Without proxy support, unknown destinations should become deny/fail-closed with an approve-then-rerun UX, not silent allow.

### 7. Use pinned BPF resources for restart tolerance

Use `bpf_link` and pin links/maps under a per-session bpffs path such as:

```text
/sys/fs/bpf/agentsh/<session>/...
```

Pinned resources let enforcement survive helper/supervisor restarts. Cleanup should follow session/cgroup lifetime, not helper process lifetime.

### 8. Implement an enforcement-tier ladder

At session start, select and record the strongest available enforcement tier:

1. helper + eBPF redirect/gate + proxy: full network policy and approvals;
2. user namespace / network namespace + nftables + proxy, where available;
3. Landlock TCP pin-to-proxy + seccomp blocking UDP/raw/QUIC bypasses: degraded TCP-focused safety;
4. no enforcement: refuse autonomous networked mode, loopback-only mode, or explicit degraded warning.

`policy-test`, session metadata, and session start output should report the active enforcement tier so policy/runtime divergence is visible.

Relevant files to inspect:

- `internal/api/app.go` (`cgroupHook`)
- `internal/api/cgroups.go` (`applyCgroupV2` and eBPF required/enforce handling)
- `internal/api/exec.go` / `internal/api/exec_stream.go`
- detached supervisor/session startup and `NewApp` wiring for cgroup manager
- `internal/netmonitor/ebpf/*`

## Expected behavior
For a `pi-autonomous` session where `policy-test` returns `approve` for `example.com:443`:

- the real `curl https://example.com` connect should prompt for network approval; or
- if eBPF/cgroup enforcement cannot be attached and `ebpf.required = true`, the command should fail closed before network access; and
- audit/session events should include cgroup/eBPF setup and network decision events, not just command start/finish.

## Regression test idea
Add an integration/NixOS/VM check that starts a detached `pi-autonomous` session with eBPF required/enforced, runs a command that connects to `example.com:443`, and asserts one of:

- an approval is requested for `approve-unknown-https`; or
- enforcement setup fails closed before the connect.

It must fail if the command returns HTTP 200 with no approval/network/cgroup/eBPF event.
