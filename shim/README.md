# Environment Variable Interception Shims

This directory contains native code shims that intercept environment variable access
at runtime. These provide Layer 2 protection (see §7 in the spec) to prevent agents
from bypassing environment filtering by directly reading `/proc/self/environ` or
using native APIs.

## Overview

| Platform | Mechanism | File |
|----------|-----------|------|
| Linux | `LD_PRELOAD` | `linux/libenvshim.so` |

## How It Works

The shims intercept standard library functions for environment variable access:

- `getenv()`, `setenv()`, `putenv()`, `unsetenv()`

When a blocked variable is accessed, the shim returns NULL (or empty) as if the
variable doesn't exist, and emits an event to the agentsh daemon.

## Configuration

Policy is loaded from `/etc/agentsh/env-policy.conf` (or path in `AGENTSH_ENV_POLICY_FILE`):

```conf
# Mode: allowlist (default, more secure) or blocklist
mode=blocklist

# Variables to block (glob patterns supported)
blocked=*_KEY,*_TOKEN,*_SECRET,*_PASSWORD,AWS_*,GITHUB_*

# Sensitive patterns for logging (substring match)
sensitive=KEY,TOKEN,SECRET,PASSWORD,CREDENTIAL

# Enable/disable event logging
log_access=true
```

## Building

```bash
cd linux
make
# Test
make test
```

## Usage

```bash
LD_PRELOAD=/path/to/libenvshim.so your_command
```

## Event Logging

Events are sent to the agentsh daemon via Unix socket at `/run/agentsh/env.sock` (or `AGENTSH_ENV_SOCKET`).

Event format (JSON):

```json
{
  "type": "env_read",
  "timestamp": 1703520000.123456789,
  "decision": "deny",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "AWS_SECRET_KEY",
    "operation": "read",
    "sensitive": true,
    "pid": 12345
  }
}
```

## Limitations

- `LD_PRELOAD` has no effect on statically linked binaries or on setuid/setgid binaries.
