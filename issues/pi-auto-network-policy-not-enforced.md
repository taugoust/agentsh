# pi-auto network policy approval is not enforced at runtime

## Status
Open.

## Current mitigation
Detached supervisors now print a prominent warning when the source config enables network enforcement that the current detached MVP disables. This keeps `pi-auto` usable while making the safety gap visible.

Partial hardening has landed for adjacent bugs: cgroup hooks now activate for eBPF-only configs, and exec runners fail closed on cgroup/eBPF post-start hook errors. The core detached network-enforcement gap remains open.

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

On NixOS machines, this can be installed as a system service. On home-manager-only machines with `sudo`, support a sudo-launched per-session helper path if feasible. With no helper available, do not claim full network enforcement.

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
