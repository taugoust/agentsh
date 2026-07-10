# pi-auto network policy approval is not enforced at runtime

## Status
Open for the Home Manager-only TUM DOS deployment and removal of an obsolete strict-startup warning. Strict local sessions are working on both `matebook` and `virby-vm`.

## Deployment status (2026-07-10)

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

### Strict startup warning — obsolete noise

Successful strict sessions still print this pre-preflight migration warning:

```text
agentsh: warning: detached supervisor is preserving required/enforced eBPF network setup (sandbox.network.enabled, sandbox.network.transparent.enabled, sandbox.network.ebpf.enabled, sandbox.network.ebpf.enforce, sandbox.network.ebpf.required); strict session startup will refuse unless the disposable cgroup/helper/proxy/command-jail/bypass preflight reports ready, and every command remains behind the fail-closed setup barrier
```

It comes from `detachedSupervisorNetworkEnforcementWarning` in `internal/cli/supervisor_session.go`. This warning was useful while detached networking was unsupported, but configured strict networking is now the expected path and the active preflight is authoritative. Do not warn merely because strict settings are being preserved. Keep explicit diagnostics for degraded best-effort behavior and surface actual launch/preflight failures; if useful, move the successful-path explanation to debug/verbose output.

### TUM DOS Home Manager hosts — sudo system helper required

The current `hosts/work/dos.nix` configuration explicitly disables detached-supervisor discovery, cgroups, network enforcement, and eBPF. Home Manager can install the unprivileged AgentSH/Pi client configuration, but it cannot safely own the required root service.

These hosts need an explicit, trusted sudo bootstrap on each machine that:

- installs a root-owned, socket-activated nethelper for the actual `theo` UID;
- uses a host-local root-owned credential source and the protected per-UID runtime copy;
- pins an immutable AgentSH package with a root GC root rather than executing `~/.nix-profile/bin/agentsh` as root;
- ensures bpffs, cgroup v2, user-manager delegation/lingering, systemd credentials, and unprivileged namespaces are available; and
- leaves ordinary `pi`/`pi-auto` sessions unprivileged and free of per-session sudo prompts.

Do not run sudo from Home Manager activation. Add an explicit install/status/uninstall command, pilot it on one x86_64 and one AArch64 DOS host, and only enable strict DOS policy after the active preflight passes. Deploy the root system units separately on every host; the shared home directory is not sufficient.

## Remaining work

- [ ] Remove or downgrade the successful strict-startup warning without weakening fail-closed startup or failure diagnostics.
- [ ] Implement the portable sudo-installed DOS helper and Home Manager client wiring.
- [ ] Pilot DOS deployment on one x86_64 and one AArch64 host before fleet rollout.

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

This gives the supervisor a writable delegated subtree while keeping it unprivileged. For SSH use, handle user-manager availability explicitly (`XDG_RUNTIME_DIR`, lingering, remote user systemd). If delegation is unavailable, fall back to lower enforcement tiers or degraded warning.

### 4. Add a narrow privileged network helper

Introduce a small helper/service that:

- runs with the minimal required privileges/caps for BPF/network setup;
- loads only AgentSH's fixed, built-in BPF programs;
- never accepts arbitrary BPF bytecode or privileged fds from clients;
- attaches `bpf_link`s to requested cgroups;
- updates allow/deny/redirect maps on supervisor request;
- owns cleanup/reaping; and
- never runs Pi/tools or arbitrary commands.

On NixOS machines, this can be installed as a system service. On Home Manager-only machines with `sudo`, use an explicit trusted bootstrap to install the same root-owned, socket-activated per-UID service; do not launch a fresh privileged helper from every Pi session or invoke sudo from Home Manager activation. With no installed helper available, do not claim full network enforcement.

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
