# pi-auto detached network enforcement reporting readiness

## Inspection summary

- `internal/cli/supervisor_session.go` already computes `NetworkEnforcement` and writes it into detached `metadata.json`. `agentsh session start --detach --json` includes the object because the start result embeds supervisor metadata. Current local plumbing can also report a helper-requested degraded tier when `AGENTSH_NETHELPER_SOCKET` is configured, but it deliberately keeps `network_policy_enforced=false`.
- The non-JSON `agentsh session start --detach` path now prints the detached network enforcement summary/warning from metadata under the supervisor/worktree lines.
- `agentsh session list` can fall back to raw detached metadata JSON when the main daemon is unavailable, so `network_enforcement` is visible to tools there. The daemon-side `/api/v1/detached-supervisors` endpoint also passes `network_enforcement` through.
- `agentsh debug policy-test` now reports the policy decision/rule/reason/source and, for network operations, a `runtime_enforcement` section/object with the active/degraded tier, proxy path, fail-closed setup status, and whether direct bypass blocking is only after successful per-command attach.
- `nix-config/packages/pi-auto/pi-auto.sh` parses session id, worktree, runtime paths, supervisor socket, event token, state dir, and workspace roots from `agentsh session start --json`; it currently discards `network_enforcement`.
- `pi-auto` launch banners and prompt context say AgentSH owns network policy, but do not include the active detached enforcement tier. The remembered pi-auto state files also do not store it.
- The Pi sandbox extension attaches via `AGENTSH_SESSION_SUPERVISOR` and can query `/api/v1/sessions/{id}` or `/api/v1/sessions/{id}/network-enforcement`; both now expose the supervisor's normalized runtime evidence. Downstream extension status/help integration remains separate work.

## Suggested user-facing tier text

### No enforcement

```text
Network enforcement: none (network policy is not enforced at runtime)
WARNING: Network policy checks may report approvals/denies, but commands can still connect. Do not treat pi-auto network approvals as enforced.
```

### Cgroup-delegated-only

```text
Network enforcement: cgroup-delegated-only (cgroup placement available; helper/proxy not active)
WARNING: A delegated cgroup is available, but network policy is not yet enforced. Unknown destinations are not approval-gated at runtime.
```

### Helper requested but degraded

```text
Network enforcement: helper requested (degraded; network policy is not proven enforced)
WARNING: Helper/proxy setup is requested, but transparent proxy redirection, same-UID socket/fd isolation, and installed-service cleanup/restart recovery are not all proven active.
```

### Proven proxy-required enforcement

```text
Network enforcement: ready (helper+eBPF proxy-required tier proven)
Proxy-aware HTTP(S) is synchronously policy-gated; direct and unsupported command traffic is fail-closed.
```

This label does not require or imply transparent redirect compatibility.

## Integration steps after current dirty implementation files settle

1. Update `pi-auto.sh` `parse_started_session` to retain `network_enforcement` from start JSON, store it in pi-auto state files, print it in local and remote launch banners, and include the warning in the parent Pi prompt context.
2. Update the sandbox extension to consume the supervisor session/network-enforcement API; do not pass a launch-time JSON object as if it were live evidence.
3. Update the sandbox extension status/help output to show the tier and issue a warning notification on attach when `network_policy_enforced` is not true.
4. Preserve compatibility while detached mode is required by `pi-auto`: warn loudly for `none`, `cgroup-delegated-only`, `helper-ebpf-gate` degraded, and `helper-ebpf-proxy` degraded tiers; only consider failing autonomous startup after a full helper/proxy or loopback-only fallback exists.

## Blockers

- AgentSH now has the NixOS root helper/socket module, protected per-UID runtime credential contract, delegated transient user-supervisor launch, stopped-child command jail, and active disposable helper/boundary/bypass preflight. These paths remain unexecuted in this checkout and still require installed-host/kernel and crash/reload acceptance; direct/home-manager launch remains degraded.
- `pi-auto` wrapper/banner/state integration remains downstream work and is intentionally not changed from this repository.
- `network_policy_enforced=true` remains blocked until the proxy-required tier's installed boundary and bypass tests pass. Transparent redirect is optional and is not a prerequisite.
