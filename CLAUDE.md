# Claude Code Guidelines

Read and follow [AGENTS.md](./AGENTS.md) for development rules.

## Project Structure

- `cmd/` - CLI entry points
- `internal/` - Private packages
- `pkg/` - Public packages
- `internal/platform/` - Platform abstraction and the Linux implementation

## Build & Test

```bash
nix build --no-link .#agentsh     # Build
nix flake check                   # Run all checks
```

## Before Committing

1. Run the relevant flake checks (or `nix flake check`)
2. Check for hardcoded paths
