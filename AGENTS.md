# Agent Guidelines

This project cross-compiles to Linux, macOS, and Windows. Follow these rules.

## Paths

- Use `filepath.Join()` for all path construction
- Use `os.TempDir()` instead of hardcoded `/tmp`
- Use `filepath.Separator` if you need the separator character
- Never hardcode `/` or `\` as path separators

## OS-Specific Code

- Use build tags for platform-specific files: `//go:build linux`, `//go:build darwin`, `//go:build windows`
- Check `runtime.GOOS` for runtime platform detection
- Skip platform-specific tests with `t.Skip()` when features aren't available

## Common Platform Differences

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Unix sockets | Yes | Yes | No |
| PTY | /dev/ptmx | /dev/ptmx | ConPTY |
| Resource limits | cgroups | RLIMIT_* | Job Objects |
| Signals | Full POSIX | Full POSIX | Limited |
| $0 / argv[0] | Works | Works | Different |

## Nix-native build and test workflow

- Run repository builds and tests through flake outputs, for example `nix build --no-link .#agentsh`, a focused `.#checks.<system>.<name>` output, or `nix flake check`.
- Do not invoke `go build` or `go test` directly, including through `nix develop -c`. If focused validation is missing, add a deterministic flake check instead of bypassing Nix.
- Put `GOOS` cross-compilation coverage inside a flake check; do not run ad hoc cross-build commands from an agent session.
- Tests using Unix sockets, POSIX signals, or shell features should skip on Windows.
- Use `t.TempDir()` for test directories (auto-cleaned)

## CI-Specific Issues

**ConPTY tests hang in CI:** Windows ConPTY doesn't properly signal EOF in non-interactive environments. Tests using ConPTY should skip in CI:

```go
func skipInCI(t *testing.T) {
    t.Helper()
    if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
        t.Skip("skipping ConPTY test in CI")
    }
}
```

## Environment Variables

- Use `os.Getenv()` / `os.Setenv()`
- On Windows, env vars are case-insensitive but Go preserves case
- Use `os.Environ()` to get the full environment as `KEY=value` slice

## Issue Tracking

- Track open work in `issues/*.md`; move completed issues to `issues/resolved/*.md`.
- When resolving an issue, update `## Status` to `Resolved.` and add a brief `## Resolution` section with the commit hash(es) that fixed it.
- Keep implementation plans out of tracked issues unless explicitly requested. Local/planning notes belong under ignored plan paths such as `plans/` or `issues/plans/`.
