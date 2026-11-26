# Agent Guidelines

This project targets Linux only. Follow these rules.

## Paths

- Use `filepath.Join()` for path construction
- Use `os.TempDir()` or `t.TempDir()` instead of hardcoded `/tmp`

## Linux-Specific Code

- Kernel-dependent code (seccomp, eBPF, Landlock, cgroups, namespaces, ptrace) uses `//go:build linux` or a `_linux.go` suffix; cgo-dependent code adds `cgo` (`//go:build linux && cgo`) with a `!linux || !cgo` stub so `CGO_ENABLED=0` builds still compile
- Do not add macOS, Windows, or other non-Linux ports, stubs, or `runtime.GOOS` branches
- Skip tests with `t.Skip()` when a kernel feature or privilege isn't available in the test environment

## Nix-native build and test workflow

- Run repository builds and tests through flake outputs, for example `nix build --no-link .#agentsh`, a focused `.#checks.<system>.<name>` output, or `nix flake check`.
- Do not invoke `go build` or `go test` directly, including through `nix develop -c`. If focused validation is missing, add a deterministic flake check instead of bypassing Nix.
- Use `t.TempDir()` for test directories (auto-cleaned)

## Environment Variables

- Use `os.Getenv()` / `os.Setenv()`
- Use `os.Environ()` to get the full environment as `KEY=value` slice

## Issue Tracking

- Track open work as GitHub Issues on `taugoust/agentsh`. Do not add issue files to the repository.
- Keep implementation plans out of issues unless explicitly requested. Local/planning notes belong under ignored plan paths such as `plans/`.
