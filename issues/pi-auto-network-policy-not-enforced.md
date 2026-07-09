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

The real fix still needs a supported detached network-enforcement design (for example a privileged parent/daemon handoff, transparent proxy support, or another mechanism). Landlock network on the tested kernel is available but too coarse here: the current wrapper only allows or blocks TCP generally, not per-host dynamic approval.

Already-landed partial hardening:

- activate `cgroupHook` for eBPF-only configs; and
- propagate post-start hook errors as command failures instead of logging-and-continuing.

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
