# Security

This document describes the threat model, security mechanisms, and known limitations of agentsh.

## Overview

agentsh is a security sandbox for AI agent command execution. It interposes between an AI agent and the host system to enforce policies on file access, network connections, command execution, and environment variables.

## Threat Model

### What agentsh Protects Against

agentsh is designed to mitigate risks from **semi-trusted AI agents** operating within a defined workspace:

| Threat | Protection |
|--------|------------|
| Arbitrary file access | FUSE filesystem with policy-based access control |
| Credential theft via files | Deny rules for `.ssh/`, `.aws/`, `.env`, etc. |
| Credential theft via environment | Deny list for secrets + dangerous vars (LD_PRELOAD, etc.) |
| Unauthorized network access | eBPF/policy-based network filtering |
| Dangerous command execution | Command allowlists with args pattern matching; kernel-level enforcement via seccomp or ptrace |
| Resource exhaustion | cgroup limits (memory, CPU, PIDs) |
| Destructive operations | Approval workflows, soft-delete to trash, checkpoint/rollback |
| PII leakage to LLMs | Embedded proxy with DLP redaction before requests reach provider |
| Untracked LLM usage | Request/response logging with token usage for cost attribution |
| Unauthorized signal delivery | Signal interception with policy-based allow/deny/redirect |
| Process termination attacks | Signal rules blocking fatal signals to external/system processes |

### What agentsh Does NOT Protect Against

agentsh is **not** a full security sandbox like a VM or container with seccomp. It does not protect against:

| Threat | Reason |
|--------|--------|
| **Kernel exploits** | Runs in userspace; kernel bugs bypass all protections |
| **Root-level attacks** | Assumes agent runs as unprivileged user |
| **Hardware side-channels** | No protection against Spectre/Meltdown-class attacks |
| **Malicious agentsh binary** | Assumes agentsh itself is not compromised |
| **Pre-existing malware** | Does not scan for or remove existing threats |
| **Social engineering** | Cannot prevent agent from outputting phishing content |
| **Denial of service to host** | Resource limits help but don't fully prevent |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                         HOST SYSTEM                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    agentsh daemon                      │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │  │
│  │  │   Policy    │  │    FUSE     │  │    eBPF      │   │  │
│  │  │   Engine    │  │  Intercept  │  │   Network    │   │  │
│  │  └─────────────┘  └─────────────┘  └──────────────┘   │  │
│  │  ┌─────────────┐  ┌─────────────┐                     │  │
│  │  │   Ptrace    │  │   Seccomp   │                     │  │
│  │  │  Intercept  │  │   Filter    │                     │  │
│  │  └─────────────┘  └─────────────┘                     │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │              AGENT SANDBOX                       │  │  │
│  │  │  • Restricted file access (/workspace only)     │  │  │
│  │  │  • Filtered environment variables               │  │  │
│  │  │  • Controlled network egress                    │  │  │
│  │  │  • Resource limits (cgroups)                    │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Trust assumptions:**
- The host kernel is trusted
- The agentsh binary is trusted
- Policy files are trusted (not writable by agent)
- The AI agent is semi-trusted (may attempt policy violations)

## Security Mechanisms

### File Access Control (FUSE)

- Virtual filesystem mounted at `/workspace`
- All file operations intercepted and checked against policy
- Symlink escape prevention via `EvalSymlinks` + boundary checks
- Operations: read, write, create, delete, chmod, rename, etc.

**Policy evaluation:** First matching rule wins. Default is deny.

#### Deferred FUSE Mounting

In some environments (E2B, Firecracker, or other snapshot-based sandboxes), `/dev/fuse` is not accessible at session creation time but becomes available later at runtime. Deferred FUSE mounting delays the mount until the first `exec` call, then mounts idempotently.

**When to use:**
- Snapshot-restore environments where device permissions change at runtime
- Firecracker microVMs where `/dev/fuse` is gated behind a readiness marker
- Any setup where FUSE availability is delayed relative to session creation

**Configuration:**

```yaml
sandbox:
  fuse:
    enabled: true
    deferred: true
    # Optional: only run enable command when this file exists
    deferred_marker_file: "/tmp/.agentsh-fuse-enabled"
    # Optional: command to make /dev/fuse accessible
    deferred_enable_command: ["sudo", "/bin/chmod", "666", "/dev/fuse"]
```

**Behavior:**
- On each `exec`, `ensureFUSEMount` checks if FUSE is already mounted (idempotent no-op if so)
- Calls `Recheck()` on the filesystem interceptor to re-probe `/dev/fuse`
- If still unavailable and `deferred_enable_command` is configured, runs the command (gated by `deferred_marker_file` if set)
- On success, mounts the FUSE overlay and emits a `fuse_mounted` event with `"deferred": true`
- On failure, emits `fuse_mount_failed` and continues without FUSE (non-blocking)

**Security considerations:**
- The enable command runs as the agentsh process (not as the agent). If it uses `sudo`, ensure the sudoers policy is scoped to the specific command.
- The marker file should be writable only by trusted infrastructure (not by the agent), since its presence triggers the enable command.
- If `deferred_enable_command` is empty, no automatic enable is attempted — FUSE must become available through external means.

### Network Control (eBPF)

- Attaches to process cgroup before execution begins
- Filters connections by domain, CIDR, and port
- DNS resolution for domain-based rules (with timeout)

**Race condition mitigation:** Processes start in ptrace-stopped state; eBPF attaches before process resumes.

### Command Execution

- Pre-execution policy check on command + arguments
- Three matching modes:
  - **Basename:** `sh` matches any path ending in `/sh`
  - **Full path:** `/bin/sh` matches only that exact path
  - **Glob pattern:** `/usr/*/python3` matches `/usr/bin/python3`, `/usr/local/python3`
- Args pattern matching for dangerous flag combinations
- **Path canonicalization:** `filepath.EvalSymlinks` resolves symlinks before policy evaluation, preventing bypass via symlinks or `/proc/self/root` paths (relative path resolution is applied for `execveat` calls)
- **Transparent command unwrapping:** Wrapper commands (env, sudo, nice, ld-linux, etc.) are unwrapped to find the real payload; both wrapper and payload are evaluated with the most restrictive decision winning

**Default behavior:** Deny if no rule matches.

### Command Execution Enforcement (ptrace)

In environments where seccomp user-notify is unavailable (e.g. AWS Fargate, restricted containers), agentsh uses ptrace-based syscall interception as an alternative enforcement mechanism.

**Implementation:**
- Uses `PTRACE_SEIZE` to attach without stopping the target process
- Intercepts `execve(2)` and `execveat(2)` syscalls at entry
- Reads filename and argv from tracee process memory via `/proc/<tid>/mem`
- Evaluates the same policy rules as seccomp mode
- Deny: sets syscall number to -1 (invalid), then fixes up return value with `-EACCES` on exit
- Auto-attaches to fork/clone/vfork children via `PTRACE_O_TRACECLONE`/`TRACEFORK`/`TRACEVFORK`

**Security properties:**
- Kernel-level enforcement: the denied syscall never executes
- Process tree tracking: all descendants are traced, preventing escape via fork+exec
- `execveat` with `AT_EMPTY_PATH` (fd-based exec) is intercepted alongside regular `execve`
- Path resolution: relative paths and fd-based paths are resolved to absolute paths for policy evaluation

**Limitations:**
- Currently intercepts execve/execveat only (Phase 1); file, network, and signal syscalls are classified but auto-allowed
- Small race window between fork and ptrace auto-attach
- Requires `SYS_PTRACE` capability (Linux-only)

**Configuration:** See [Security Modes - Ptrace Configuration](docs/security-modes.md#ptrace-configuration).

### Environment Variables

- Deny list for known secrets (AWS keys, API tokens, etc.)
- Deny list for code injection vectors:
  - Dynamic loader: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`
  - Languages: `PYTHONPATH`, `NODE_OPTIONS`, `RUBYLIB`, `PERL5LIB`
  - Shell: `BASH_ENV`, `ENV`, `PROMPT_COMMAND`
- Allow/deny patterns configurable per-policy

**Operator-trusted injection (`env_inject`):**

The `sandbox.env_inject` configuration allows operators to inject environment variables that bypass policy filtering. This is intentionally powerful and should only be used by operators with config file access.

Primary use case: Setting `BASH_ENV` to point to a script that disables shell builtins (`kill`, `enable`, `ulimit`) which would otherwise bypass seccomp enforcement.

```yaml
sandbox:
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
```

**Security properties:**
- `env_inject` values bypass the deny list (operator explicitly wants them)
- Policy-level `env_inject` overrides global config (for per-policy customization)
- Trust boundary: config file access (not user-controllable)

### Resource Limits (cgroups v2)

- Memory limits (with swap disabled)
- CPU quota
- Process count limits
- Command and session timeouts

### Signal Interception

agentsh intercepts signal delivery between processes using seccomp user-notify, providing policy-based control over which signals can reach which targets.

**Implementation:**
- Uses `SECCOMP_RET_USER_NOTIF` to trap signal syscalls (`kill`, `tkill`, `tgkill`, etc.)
- PID registry tracks all processes in the session for target classification
- Policy rules evaluated based on signal, sender, and target relationship

**Target Classification:**

| Target Type | Description |
|-------------|-------------|
| `self` | Process signaling itself |
| `children` | Direct child processes |
| `descendants` | All descendant processes |
| `session` | Any process in agentsh session |
| `external` | PIDs outside session |
| `system` | PID 1 and kernel threads |

**Decision Types:**

| Decision | Behavior |
|----------|----------|
| `allow` | Signal delivered normally |
| `deny` | Returns EPERM to sender |
| `redirect` | Changes signal (e.g., SIGKILL → SIGTERM) |
| `audit` | Allow + log event |

See [Policy Documentation](docs/operations/policies.md#signal-rules) for configuration examples.

### Approval Workflows

Risky operations can require human approval before execution. agentsh supports multiple approval modes:

**Approval Modes:**
- `local_tty`: Interactive terminal prompt with math challenge (default)
- `api`: Remote approval via REST API (for headless/remote deployments)
- `totp`: Time-based One-Time Password via authenticator app (Google Authenticator, Authy, etc.)
- `webauthn`: Hardware security key verification (YubiKey, platform authenticators) - highest security

**Key Features:**
- Configurable timeout (default: deny on timeout)
- Audit logging of all approval decisions
- Credential separation prevents agents from self-approving
- WebAuthn provides cryptographic proof of human presence

See [Approval Authentication](docs/approval-auth.md) for detailed configuration.

### Checkpoint and Rollback

agentsh provides workspace checkpoint and rollback capabilities for recovery from destructive operations:

**Core Features:**
- **Copy-on-write snapshots**: File contents backed up before risky commands
- **Hash verification**: SHA-256 verification ensures rollback integrity
- **Auto-checkpoint triggers**: Automatic checkpoints before rm, mv, git reset, etc.
- **Diff inspection**: Compare current workspace to checkpoint state
- **Purge management**: Retention policies for storage management

**CLI Commands:**
```bash
# Create manual checkpoint
agentsh checkpoint create --session <id> --workspace /path

# List checkpoints
agentsh checkpoint list --session <id>

# Show checkpoint details and diff
agentsh checkpoint show <cp-id> --session <id> --workspace /path --diff

# Preview rollback (dry-run)
agentsh checkpoint rollback <cp-id> --session <id> --workspace /path --dry-run

# Perform rollback
agentsh checkpoint rollback <cp-id> --session <id> --workspace /path

# Purge old checkpoints
agentsh checkpoint purge --session <id> --older-than 24h --keep 10
```

**Auto-Checkpoint Configuration:**
```yaml
sessions:
  checkpoints:
    enabled: true
    storage_dir: /var/lib/agentsh/checkpoints
    max_per_session: 50
    auto_checkpoint:
      enabled: true
      triggers:
        - rm
        - mv
        - git reset
        - git checkout
        - git clean
        - git stash
    retention:
      max_age: 168h  # 7 days
```

**Default Auto-Checkpoint Triggers:**
| Command | Risk |
|---------|------|
| `rm`, `rmdir`, `unlink` | File deletion |
| `mv`, `rename` | File movement (source lost) |
| `git reset` | Uncommitted changes lost |
| `git checkout` | Local modifications discarded |
| `git clean` | Untracked files deleted |
| `git stash` | Changes stashed (may be forgotten) |

**Safety Features:**
- Skips files larger than 100MB by default
- Skips hidden directories (.git, etc.)
- Dry-run mode for rollback preview
- Hash verification prevents corrupted restores

**Limitations:**
- Checkpoints only cover files, not external state (databases, APIs)
- Large workspaces may require significant storage
- Cannot checkpoint files outside the workspace

### External KMS Integration

agentsh supports external Key Management Systems for HMAC keys used in audit integrity chains:

**Supported Providers:**
| Provider | Key Source | Envelope Encryption |
|----------|------------|---------------------|
| File/Env | Local file or environment variable | No |
| AWS KMS | AWS Key Management Service | Yes (GenerateDataKey) |
| Azure Key Vault | Azure Key Vault secrets | No (direct secret) |
| HashiCorp Vault | Vault KV v1/v2 secrets | No (direct secret) |
| GCP Cloud KMS | Google Cloud KMS | Yes (Encrypt/Decrypt) |

**Configuration Examples:**

```yaml
# AWS KMS (envelope encryption)
audit:
  integrity:
    enabled: true
    key_source: aws_kms
    aws_kms:
      key_id: "arn:aws:kms:us-east-1:123456789:key/abc-123"
      region: us-east-1
      encrypted_dek_file: /etc/agentsh/audit-dek.enc  # Cache encrypted DEK

# Azure Key Vault
audit:
  integrity:
    enabled: true
    key_source: azure_keyvault
    azure_keyvault:
      vault_url: "https://myvault.vault.azure.net"
      key_name: "agentsh-audit-key"
      key_version: ""  # Empty = latest

# HashiCorp Vault
audit:
  integrity:
    enabled: true
    key_source: hashicorp_vault
    hashicorp_vault:
      address: "https://vault.example.com:8200"
      auth_method: kubernetes  # token, kubernetes, approle
      kubernetes_role: agentsh
      secret_path: "secret/data/agentsh/audit-key"
      key_field: "hmac_key"

# GCP Cloud KMS
audit:
  integrity:
    enabled: true
    key_source: gcp_kms
    gcp_kms:
      key_name: "projects/my-proj/locations/us/keyRings/agentsh/cryptoKeys/audit"
      encrypted_dek_file: /etc/agentsh/audit-dek.enc
```

**Authentication:**
- **AWS**: Uses default credential chain (env vars, shared config, IAM role)
- **Azure**: Uses DefaultAzureCredential (managed identity, CLI, env vars)
- **Vault**: Supports token, Kubernetes, and AppRole authentication
- **GCP**: Uses Application Default Credentials

**Key Caching:**
- Keys are cached in memory after first retrieval
- For envelope encryption (AWS/GCP), encrypted DEK can be cached to disk
- Key refresh requires service restart

### Authentication and Authorization

agentsh supports multiple authentication methods for API access:

**Authentication Types:**
- `api_key`: Static API keys with role-based access (agent, approver, admin)
- `oidc`: OpenID Connect/OAuth 2.0 for enterprise SSO integration (Okta, Azure AD, etc.)
- `hybrid`: Both API key and OIDC accepted (API key takes precedence)

**OIDC Features:**
- JWT validation with JWKS auto-discovery
- Group-based role mapping (groups containing "admin" or "approver" keywords)
- Allowed groups filtering for access control
- Token caching with secure hashing

**Role Separation:**
- `agent` role: Can execute commands, cannot approve
- `approver` role: Can view and resolve approval requests
- `admin` role: Full access including policy management

```yaml
# Example hybrid auth configuration
auth:
  type: hybrid
  api_key:
    keys_file: /etc/agentsh/api-keys.yaml
  oidc:
    issuer: "https://corp.okta.com"
    client_id: "agentsh"
    audience: "agentsh"
    allowed_groups: ["agentsh-operators"]
```

### MCP Security

agentsh provides comprehensive security controls for Model Context Protocol (MCP) tool invocations:

#### Tool Whitelisting

Policy-based control over which MCP tools can be invoked:

```yaml
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true
    tool_policy: allowlist
    allowed_tools:
      - server: "filesystem"
        tool: "read_file"
      - server: "github"
        tool: "*"
```

| Policy Mode | Behavior |
|-------------|----------|
| `allowlist` | Only explicitly listed tools are permitted |
| `denylist` | Listed tools are blocked, all others allowed |
| `none` | No policy enforcement |

#### Version Pinning

Detect and optionally block MCP tool definition changes (rug pull detection):

```yaml
sandbox:
  mcp:
    version_pinning:
      enabled: true
      on_change: block  # block, alert, allow
      auto_trust_first: true
```

CLI management:
```bash
agentsh mcp pins list
agentsh mcp pins trust --server github --tool create_issue --hash sha256:...
agentsh mcp pins reset --server github --tool create_issue
```

#### Rate Limiting

Token bucket rate limiting for MCP calls and network requests:

```yaml
sandbox:
  mcp:
    rate_limits:
      enabled: true
      default_rpm: 120
      default_burst: 20
      per_server:
        "slow-api":
          calls_per_minute: 30
          burst: 5
  network:
    rate_limits:
      enabled: true
      global_rpm: 600
      global_burst: 50
      per_domain:
        "api.openai.com":
          requests_per_minute: 60
          burst: 10
```

### LLM Proxy and Data Loss Prevention (DLP)

agentsh includes an embedded HTTP proxy that intercepts all LLM API requests from agents:

**Architecture:**
- Proxy starts automatically with each session on a random port
- Agent environment is configured to route through proxy (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`)
- Requests are intercepted, processed, and forwarded to upstream LLM providers

**DLP Redaction:**
- Request bodies are scanned for PII using regex patterns
- Matches are replaced with `[REDACTED:pattern_type]` before forwarding
- Built-in patterns: email, phone, credit card, SSN, API keys
- Custom patterns can be defined for organization-specific data

**Audit Logging:**
- All requests and responses logged to session storage (JSONL format)
- Token usage extracted and normalized across providers
- Redaction events tracked with field paths and pattern types

**Dialect Detection:**
- Anthropic: `x-api-key` or `anthropic-version` headers
- OpenAI API: `Authorization: Bearer sk-*` tokens
- ChatGPT: OAuth tokens (non-sk- Bearer tokens)

**Limitations:**
- Only scans text content (not images or encoded data)
- Regex patterns may miss obfuscated PII
- Agent could theoretically bypass proxy (combine with network rules for defense in depth)

See [LLM Proxy Documentation](docs/llm-proxy.md) for configuration and usage details.

## Known Limitations

### TOCTOU (Time-of-Check-Time-of-Use)

File policy is checked when a file is opened. Between open and subsequent reads/writes, the underlying file could theoretically change (e.g., via hard links from outside the sandbox). This is inherent to userspace filesystem interception.

**Mitigation:** The window is small, and the agent cannot create hard links to files outside `/workspace`.

### DNS Rebinding

Network rules based on domain names resolve DNS at connection time. An attacker controlling DNS could potentially:
1. Resolve `evil.com` to an allowed IP during policy check
2. Change DNS to point to a blocked IP for actual connection

**Mitigation:** Use CIDR rules for critical blocks (e.g., metadata services at `169.254.169.254/32`). Domain rules are convenience, not security boundaries.

### Process Tree Escapes

If the eBPF/cgroup attachment fails after process start, child processes might execute before controls are in place.

**Mitigation:** Ptrace-stopped start ensures attachment completes before any user code runs. Hook failures result in process termination.

### Transparent Unwrap Heuristic

The transparent command unwrapping uses a simple heuristic to identify payload arguments (skip flags, env assignments, stop at first non-flag arg). This may misidentify a flag's value as the payload in some edge cases (e.g., `nice -n 10 wget` identifies `10` as the payload, not `wget`).

**Mitigation:** Misidentified payloads don't match any command rule and hit default-deny, which is the safe outcome. Network enforcement provides a backstop for the actual payload command.

### Approval Bypass via Timing

If an approval request times out, the operation is denied. However, a patient attacker could retry until a human mistakenly approves.

**Mitigation:** Audit logging; approval fatigue is a human factors problem.

## Security Defaults

| Component | Default |
|-----------|---------|
| File access | Deny (unless explicitly allowed) |
| Network access | Deny (unless explicitly allowed) |
| Command execution | Deny (unless explicitly allowed) |
| Unix sockets | Deny (unless explicitly allowed) |
| Signal delivery | Allow to self/children, deny to external/system (Linux only) |
| Environment variables | Allow (unless in deny list or explicit allow-list defined) |
| Approval timeout | Deny |

## Reporting Security Issues

If you discover a security vulnerability in agentsh:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers privately
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will coordinate disclosure timing with you.

## Security Checklist for Operators

Before deploying agentsh in production:

- [ ] Review and customize the default policy for your use case
- [ ] Ensure policy files are not writable by the agent user
- [ ] Enable audit logging and monitor for policy violations
- [ ] Set appropriate resource limits for your workload
- [ ] Use CIDR rules (not just domains) for critical network blocks
- [ ] Test approval workflows to ensure timeouts result in deny
- [ ] Run agentsh as a non-root user
- [ ] Keep agentsh updated for security fixes
- [ ] Configure DLP patterns for organization-specific sensitive data
- [ ] Enable network rules to force LLM traffic through the proxy
- [ ] Review LLM usage reports for unexpected token consumption
- [ ] Enable checkpoint/rollback for sessions running destructive commands
- [ ] Configure auto-checkpoint triggers appropriate for your workload
- [ ] For audit integrity, consider using external KMS (AWS/Azure/Vault/GCP) instead of local key files

## Changelog

| Date | Change |
|------|--------|
| 2026-11-26 | Removed the macOS and Windows ports; agentsh supports Linux only |
| 2026-05-06 | v0.19.2: shim's kernelinstall path skips wrap-init when an ancestor's seccomp filter is already inherited (`/proc/self/status` `Seccomp_filters:`), avoiding nested-stacking failures masked as `ECANCELED` on Runloop devboxes (#282). Wrap-init now appends `dirname(AgentCommand)` to Landlock `allow_execute` (#283). `agentsh-unixwrap` resolves the command path before installing the seccomp filter so `exec.LookPath` probes are not intercepted by the file-monitor handler (#283 bug B). Seccomp install raw kernel errnos are surfaced via `SCMP_FLTATR_API_SYSRAWRC`; `WAIT_KILLABLE_RECV` retry is gated on `EINVAL` (#285). |
| 2026-03-04 | Added execve hardening: path canonicalization via EvalSymlinks and transparent command unwrapping with dual evaluation |
| 2026-02-13 | Added configurable deferred FUSE mounting for snapshot-restore environments |
| 2026-01-11 | Added signal interception via seccomp user-notify for policy-based signal control (Linux) |
| 2026-01-07 | Added external KMS integration for audit integrity keys (AWS KMS, Azure Key Vault, HashiCorp Vault, GCP Cloud KMS) |
| 2026-01-07 | Added checkpoint/rollback for workspace state recovery with auto-checkpoint triggers |
| 2026-01-03 | Wired up unix socket enforcement via seccomp user-notify (Linux only) |
| 2026-01-03 | Implemented macOS sandbox-exec wrapper with SBPL profiles |
| 2026-01-03 | Implemented FUSE event emission for file operation monitoring |
| 2026-01-03 | Implemented Lima and WSL2 Linux namespace isolation via unshare |
| 2026-01-03 | Implemented Lima and WSL2 bindfs-based filesystem mounting inside VMs |
| 2026-01-03 | Implemented WSL2 cgroups v2 resource limits and iptables network interception |
| 2026-01-03 | Implemented Lima VM cgroups v2 resource limits and iptables network interception |
| 2026-01-02 | Added embedded LLM proxy with DLP redaction and usage tracking |
| 2026-01-02 | Implemented AppContainer sandbox execution with stdout/stderr capture |
| 2026-01-02 | Added ACL cleanup on AppContainer sandbox close |
| 2026-01-02 | Added WinFsp filesystem mounting with shared fuse package for Windows |
| 2026-01-02 | Added minifilter process exclusion for WinFsp coexistence |
| 2026-01-01 | Implemented macOS ESF+NE for enterprise-tier enforcement (90% security score) |
| 2026-01-01 | Added XPC bridge for System Extension ↔ Go policy engine communication |
| 2026-01-01 | Added session tracking for process-to-session mapping on macOS |
| 2025-12-31 | Implemented FUSE-T mounting for macOS file policy enforcement |
| 2025-01-01 | Added LD_PRELOAD and code injection env vars to deny list |
| 2025-01-01 | Fixed eBPF race condition with ptrace-stopped start |
| 2025-01-01 | Added full-path and glob matching for commands |
| 2025-01-01 | Changed command default from allow to deny |
