# agentsh Platform Notes

agentsh supports **Linux** only. Security features vary with the kernel version, the runtime environment, and the available privileges.

## Linux Security Levels

Linux security features vary significantly depending on kernel version, runtime environment, and available privileges. agentsh automatically detects available features and selects the best security mode.

### Environment Compatibility Matrix

| Environment | seccomp | eBPF | Landlock | FUSE | ptrace | Capabilities |
|-------------|---------|------|----------|------|--------|--------------|
| Native Linux (kernel 6.7+) | ✅ | ✅ | ✅ (ABI v4) | ✅ | ✅ | ✅ |
| Native Linux (kernel 5.13-6.6) | ✅ | ✅ | ✅ (ABI v1-3) | ✅ | ✅ | ✅ |
| Native Linux (kernel < 5.13) | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Docker (privileged) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Docker (unprivileged) | ❌* | ❌ | ✅ | ❌† | ❌‡ | ✅ |
| Docker (--cap-add SYS_PTRACE) | ❌* | ❌ | ✅ | ❌† | ✅ | ✅ |
| Kubernetes (standard) | ❌* | ❌ | ✅ | ❌† | ❌‡ | ✅ |
| AWS Fargate | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Nested containers | ❌ | ❌ | ✅ | ❌ | ❌‡ | ✅ |
| gVisor/Firecracker | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

\* Requires seccomp user-notify support in container runtime
† Requires `/dev/fuse` device and `SYS_ADMIN` capability
‡ Requires `SYS_PTRACE` capability (add via `--cap-add SYS_PTRACE` or securityContext)

### Security Mode by Environment

Based on available features, agentsh selects one of four security modes:

| Mode | Score | Typical Environment | Key Protections |
|------|-------|---------------------|-----------------|
| `full` | 100% | Native Linux, privileged containers | seccomp syscall filtering, eBPF network, FUSE filesystem |
| `ptrace` | ~90% | AWS Fargate, containers with SYS_PTRACE | ptrace execve interception, shim policy enforcement |
| `landlock` | ~85% | Unprivileged containers with FUSE | Landlock kernel sandbox + FUSE fine-grained control |
| `landlock-only` | ~80% | Unprivileged containers, restricted runtimes | Landlock kernel sandbox, shim policy enforcement |
| `minimal` | ~50% | gVisor, Firecracker, highly restricted | Capability dropping, shim policy only |

### Feature Availability by Kernel Version

| Kernel | Landlock ABI | Network Control | Filesystem Control |
|--------|--------------|-----------------|-------------------|
| 6.10+ | v5 | TCP bind/connect | Full + IOCTL |
| 6.7+ | v4 | TCP bind/connect | Full |
| 6.2+ | v3 | None | Full + truncate |
| 5.19+ | v2 | None | Full + REFER |
| 5.13+ | v1 | None | Basic |
| < 5.13 | N/A | None (use eBPF) | None (use seccomp) |

### What You Lose Without seccomp

When seccomp is unavailable (nested containers, restricted runtimes):

| Feature | With seccomp | Without seccomp | Mitigation |
|---------|--------------|-----------------|------------|
| Signal interception | Kernel-level | ❌ | PID namespace + dropped CAP_KILL |
| Abstract Unix sockets | Blocked | ❌ | Path-based sockets blocked via Landlock |
| Syscall filtering | 400+ syscalls | ❌ | Landlock + capabilities cover most cases |
| Fine-grained execution | Per-syscall | ❌ | Landlock execute paths + shim |

### What You Lose Without eBPF

When eBPF is unavailable:

| Feature | With eBPF | Without eBPF | Mitigation |
|---------|-----------|--------------|------------|
| Network visibility | All traffic | ❌ | Proxy-based monitoring |
| Connection tracking | Kernel-level | ❌ | Landlock TCP (kernel 6.7+) |
| DNS inspection | Deep | Proxy-level | DNS proxy |

### What You Gain With ptrace

When seccomp user-notify is unavailable but `SYS_PTRACE` capability is present (e.g. AWS Fargate), ptrace mode provides kernel-level execve interception:

| Feature | Without ptrace | With ptrace | Notes |
|---------|----------------|-------------|-------|
| Execution control | Shim only | Kernel-level | Intercepts execve/execveat syscalls |
| Deny enforcement | Shim check | Syscall invalidation | Returns -EACCES before exec runs |
| Fork/clone tracking | No | Yes | Auto-attaches to child processes |
| Process tree depth | No | Yes | Tracks nesting for policy decisions |
| execveat support | No | Yes | Handles fd-based exec (AT_EMPTY_PATH) |

**Typical use case:** AWS Fargate tasks where seccomp user-notify and eBPF are unavailable, but `SYS_PTRACE` is granted via `linuxParameters.capabilities.add`.

### Detection and Fallback

agentsh performs capability detection at startup:

```
INFO  security capabilities detected
        seccomp_user_notify=false    # Not available in this container
        ebpf=false                   # No CAP_BPF
        landlock=true
        landlock_abi=4               # Kernel 6.7+
        landlock_network=true        # Can restrict TCP
        fuse=false                   # No /dev/fuse
        ptrace=true                  # SYS_PTRACE available
        capabilities=true            # Can drop caps

INFO  selected security mode
        mode=ptrace
        protection_score=90%
```

### Forcing Specific Modes

Override auto-detection in configuration:

```yaml
security:
  # Force a specific mode (fails if requirements not met when strict=true)
  mode: landlock-only
  strict: true

  # Or set a minimum acceptable mode
  mode: auto
  minimum_mode: landlock-only  # Fail if only minimal is available
```

See [Security Modes](security-modes.md) for detailed mode configuration.

## Feature availability (current implementation)

- **FUSE workspace view:** FUSE3. In containers requires `/dev/fuse` + `SYS_ADMIN`.
- **FUSE event emission:** File operation events (open, read, write, create, delete, rename) are emitted to the configured EventChannel for audit logging and monitoring.
- **Process sandboxing:** namespaces via `unshare` (user, mount, PID, network namespaces).
- **Network visibility + policy enforcement:** works via the per-session proxy (DNS/connect/HTTP events).
- **Transparent netns interception:** optional, root-only (requires privileges; proxy mode works without it).
- **cgroups v2 limits:** optional; disabled by default (requires a writable cgroup base path).
- **Process execution stats:** CPU user/system time and peak memory returned in exec results.
- **seccomp syscall filtering:** via seccomp user-notify for unix socket enforcement.
- **ptrace execve interception:** via PTRACE_SEIZE for execve/execveat enforcement in restricted containers (e.g. AWS Fargate with SYS_PTRACE).
- **eBPF network enforcement:** requires cgroups v2 and root/CAP_BPF.
- **gRPC (optional):** if enabled, clients connect to `server.grpc.addr` (default `127.0.0.1:9090`). The CLI can prefer gRPC via `AGENTSH_TRANSPORT=grpc`.

## Quick start

```bash
agentsh server
```

## Detecting Available Capabilities

Use `agentsh detect` to probe your environment and see what security features are available:

```bash
# Show capabilities in table format (default)
agentsh detect

# Output as JSON for scripting
agentsh detect --output json

# Output as YAML
agentsh detect --output yaml
```

### Generating Optimized Configuration

Use `agentsh detect config` to generate a configuration snippet optimized for your environment:

```bash
# Print to stdout
agentsh detect config

# Write to file
agentsh detect config --output security.yaml

# Redirect to file
agentsh detect config > my-config.yaml
```

The generated config includes only security-related sections (`security:`, `landlock:`, `capabilities:`) that you can merge into your main configuration file.

## Troubleshooting

- **FUSE mount fails:** ensure FUSE3 is installed and, in Docker, `/dev/fuse` is present and `SYS_ADMIN` is allowed.
- **Transparent network mode fails:** run as root / with NET_ADMIN capabilities; otherwise rely on proxy mode.
- **cgroups errors:** keep `sandbox.cgroups.enabled: false` unless you have a writable cgroup v2 base path configured.
- **gRPC connection fails:** confirm `server.grpc.enabled: true`, the address/port are reachable, and (if auth is enabled) send the API key via gRPC metadata `x-api-key`.
