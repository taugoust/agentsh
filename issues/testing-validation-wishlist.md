# Testing and validation wishlist

## Status

Living wishlist. Open for iteration and prioritization.

## Purpose

Track testing and validation techniques that could improve confidence in AgentSH beyond its existing unit, integration, cross-platform, and VM coverage. This is intentionally a wishlist rather than a commitment to adopt every tool or make every check blocking.

## Current observations

- The repository has extensive example-based coverage: about 964 tracked Go test files across 145 package directories.
- The unmaintained legacy GitHub workflows have been removed; Nix is the maintained validation workflow.
- The Nix `go-unit-tests` output is now defined as the authoritative complete native Go suite (`go test -count=1 -p 2 ./...`). Its first full run and failure triage are pending explicit authorization.
- Race detection is focused on selected session, network-monitor, and API tests.
- There is no repository-wide coverage report or coverage ratchet.
- Go formatting is checked, but no general Go lint, vulnerability, dead-code, shell, or Nix validation gate is configured.
- Two native fuzz targets cover HTTP service path policy. Property-based testing with `rapid` is currently concentrated in the PostgreSQL protocol state machine.
- Native C helpers are compiled with strong warnings, but there is no static-analyzer or sanitizer gate.
- The flake emits the same broad check set on every system and represents several unsupported checks as successful skipped derivations.

## Principles

- Prefer observed behavior and security invariants over source-text assertions.
- Keep focused checks for diagnosis, but establish one authoritative complete test definition.
- Ratchet measured quality from a recorded baseline rather than introducing arbitrary global thresholds.
- Apply expensive techniques selectively where they have the best signal.
- Treat platform and kernel behavior as first-class; do not infer runtime correctness from cross-compilation alone.
- Do not accept generated successful no-op checks for unsupported platforms.
- Avoid broad suppression baselines. Every suppression should be narrow and explain why the finding is intentional.

## Highest-value foundation

### Remove legacy GitHub workflows

- Remove the unmaintained CI, release, Windows driver, and macOS notarization GitHub Actions workflows inherited from upstream.
- Do not treat those workflows as part of the maintained validation or release process.
- Reintroduce automation only when it has an explicit owner and uses the maintained Nix-native validation definitions.

### Canonical full Go test check

- Use the Nix-native `go-unit-tests` check to cover the complete native package set.
- The check is integrated but has not yet been run; its first execution and triage remain pending.
- Make this Nix check the authoritative maintained definition; do not treat removed legacy workflows as current infrastructure.
- Preserve focused lifecycle, approval, timeout, subagent, and recovery checks for fast diagnosis.
- Separate genuinely platform-specific packages instead of silently skipping them.

### Coverage visibility and ratcheting

- Produce atomic coverage profiles and package-level reports.
- Publish the baseline before enforcing thresholds.
- Prefer changed-line coverage and package-specific floors over one repository-wide percentage.
- Consider stricter expectations for pure security-decision packages such as policy, approvals, configuration, detached protocol validation, environment filtering, and authorization scope resolution.
- Exclude generated code and account explicitly for platform/syscall-only code.

### Curated Go linting

Trial a pinned `golangci-lint` configuration with high-signal analyzers, including:

- `govet`
- `staticcheck`
- `unused`
- `errcheck`
- `errorlint`
- `nilerr`
- `bodyclose`
- `noctx`
- `rowserrcheck`
- `sqlclosecheck`
- `copyloopvar`
- `ineffassign`
- `exhaustive`
- selected `gocritic` checks

Roll out incrementally by fixing findings or documenting narrow exceptions.

### Vulnerability analysis

- Add reachability-aware `govulncheck -mode=source` coverage.
- Add `osv-scanner` for lockfiles and non-Go dependency metadata.
- Decide how vulnerability-database freshness should interact with Nix reproducibility and offline evaluation.

### Repository-language validation

- Check all shell scripts with `shellcheck`.
- Check shell formatting with `shfmt --diff` if the existing style can be represented without churn.
- Check Nix formatting, not only Go formatting.
- Trial `statix` and `deadnix`, with narrow exclusions for intentional module arguments and generated expressions.
- Validate Python scripts with an appropriate lightweight linter if they remain maintained production tooling.

## Concurrency and lifecycle testing

### Broader race detection

Extend race-enabled coverage beyond the existing focused session, netmonitor, and API tests to concurrency-heavy packages such as:

- approvals;
- detached control, transport, and recovery;
- event stores and brokers;
- nethelper lease/rebind/release;
- runtime-provider state;
- proxy lifecycle;
- workspace finalization.

A maintained package list may provide better signal and runtime than an unconditional repository-wide `-race ./...` gate.

### Leak and flake detection

- Trial `go.uber.org/goleak` in long-lived concurrent packages.
- Add repeated, shuffled execution for selected stateful tests (`-shuffle=on`, bounded `-count`).
- Detect leaked processes, file descriptors, sockets, mounts, namespaces, and goroutines in integration fixtures.
- Avoid automatic retry as the default response to flakes; preserve the first failure evidence.

### Fault injection

Expand deterministic failure points around:

- process death between journal transitions;
- partial and truncated control messages;
- ENOSPC, EIO, permission changes, and atomic replacement;
- helper disappearance and socket rotation;
- clock jumps and timeout boundaries;
- cancellation racing command completion;
- event-store saturation and shutdown.

Prefer explicit failpoints and modelled outcomes over timing sleeps.

## Fuzzing and generative testing

### Native Go fuzzing

The existing HTTP service policy fuzzers are a useful start. Candidate additional boundaries include:

- policy and configuration parsing;
- detached-control framing and authentication;
- guest-control messages;
- supervisor recovery manifests;
- CLI/API JSON decoding;
- SSH and nethelper bootstrap responses;
- PostgreSQL protocol parsing;
- path normalization and environment-rule matching;
- seccomp notification decoding that can be isolated from kernel calls.

Run short deterministic fuzz smoke checks in the normal flake. Longer corpus-building runs can be separate, with discovered inputs committed as regression fixtures after review.

### Property and state-machine testing

Expand use of `rapid` or equivalent model-based testing for:

- approval state transitions and single-winner resolution;
- detached supervisor lifecycle and recovery;
- nethelper lease/rebind/release;
- workspace accept/reject/finalization;
- command ownership, cancellation, and execution lanes;
- policy overlay merge precedence;
- event-store backpressure and saturation.

For AgentSH's lifecycle-heavy code, state-machine testing is expected to have especially high value.

## Mutation testing

Trial mutation testing only on pure, security-relevant packages first:

- `internal/policy`;
- `internal/approvals`;
- `internal/config`;
- detached protocol validation;
- environment filtering;
- command and path matching;
- authorization and scope resolution.

Candidate tooling includes Gremlins or another actively maintained Go mutator pinned through Nix. Confirm Go 1.25 and build-tag compatibility before selecting a tool.

Initial runs should report surviving mutants without a blocking score. Surviving mutants should be classified as missing assertions, equivalent mutants, unreachable code, or unsuitable mutation operators. Introduce package-level score ratchets only after that triage. Exclude generated code, platform wrappers, cgo, eBPF, and kernel-dependent integration code initially.

## Dead code and architecture

### Dead-code detection

Use complementary techniques:

- package-local `unused` analysis through the Go lint gate;
- whole-program reachability with `golang.org/x/tools/cmd/deadcode` or equivalent.

Whole-program checks must include every real binary entry point and relevant OS/build-tag combination to avoid false positives for exported platform code.

### Dependency architecture

At the current package count, enforce intended import boundaries with `go-arch-lint`, `depguard`, or a small custom analyzer. Candidate invariants:

- policy and configuration packages do not depend on API/runtime layers;
- platform-neutral packages do not import OS implementation packages;
- enforcement decisions do not depend on presentation/UI packages;
- privileged process creation goes through approved wrappers;
- security-sensitive file access and command execution remain confined to reviewed packages.

A custom analyzer for project-specific fail-open patterns may provide more value than generic complexity metrics.

## Generated artifacts and compatibility

- Add regeneration-drift checks for protobuf Go files and any committed eBPF/generated assets.
- Add `buf lint` for protobuf definitions.
- Consider `buf breaking` or another compatibility check for released protocol APIs.
- Check generated shell completions and generated default policy/configuration artifacts if they are intended to be reproducible.
- Consider Go public-API compatibility checking for exported packages under `pkg/`.

## Native and platform code

### C and eBPF

- Add `clang-tidy` and Clang static-analyzer coverage for privileged userspace C helpers.
- Run ASan and UBSan behavior tests where helpers can execute without static linking or kernel privilege.
- Preserve strict warning-as-error builds.
- Exercise eBPF verifier acceptance and rejection on supported kernel families.
- Test map sizing, verifier limits, capability degradation, and fail-closed behavior across a kernel matrix.

### macOS and Windows

- Add native static analysis and tests for Swift, C#, and driver code where platform runners are available.
- Validate signing, entitlements, bundle structure, driver INF/catalog metadata, and runtime loading behavior rather than only successful compilation.
- Keep native execution checks distinct from cross-compilation checks.

## Security and supply-chain validation

- Add CodeQL coverage for Go and relevant native/platform languages.
- Generate an SBOM with Syft or equivalent for release artifacts.
- Check release binaries for expected PIE/RELRO/RPATH, interpreter, static/dynamic linkage, symbols, and signatures.
- Compare independently produced release artifacts where reproducible builds are feasible.
- Validate GoReleaser configuration and archive contents before release publication.
- Consider narrowly scoped Semgrep or custom analyzer rules for AgentSH-specific security invariants rather than a large generic ruleset.

## Performance and resource regression

- Use the existing benchmarks with `benchstat` and recorded baselines.
- Add allocation and latency budgets for policy evaluation, protocol parsing, event storage, and proxy hot paths.
- Track startup, command-launch, and shutdown latency for representative enforcement modes.
- Treat benchmark regressions as advisory until variance and runner stability are understood.

## Flake/check organization follow-up

- Run portable checks once instead of duplicating them across every system.
- Emit platform-specific checks only where supported.
- Remove successful `skipped-*` derivations.
- Distinguish native execution, cross-compilation, VM/kernel integration, and pure analysis checks by name.
- Extract the large check definition from `flake.nix` into focused `nix/checks/` modules.
- Keep expensive VM and namespace checks in the normal validation story unless an explicit tiering policy is adopted later.

## Suggested adoption order

1. Remove the unmaintained legacy GitHub workflows.
2. Run and triage the newly integrated canonical full Nix test check, then clean up the check matrix.
3. Add Go linting, `govulncheck`, shell validation, and Nix validation.
4. Add coverage reporting and package/changed-line ratchets.
5. Broaden race checks, leak checks, and deterministic fault injection.
6. Add fuzz and property/state-machine tests.
7. Trial targeted mutation testing and whole-program dead-code detection.
8. Add architecture enforcement, native analyzers, kernel matrix, CodeQL, SBOM, and release hardening.

## First canonical full-suite run

The first authorized `x86_64-linux` build evaluated every native package and failed in 17 package targets. The failing derivation was `/nix/store/5k5yplw4j9bd2vh5kz0ax63lsv5ai3ca-agentsh-go-tests-unstable-2026-06-17.drv`.

Initial failure classes:

- Nix-environment assumptions: hard-coded `/bin/echo`, `/bin/cat`, and `/bin/pwd`; `cat` absent from a deliberately reduced test `PATH`; an unwritable default home; missing FUSE include discovery; and tests that assume a checkout-relative repository root or fixture path.
- Sandbox inheritance: kernel-install tests observe the Nix builder's existing seccomp filter and cannot exercise their expected unfiltered-process transition directly.
- Stale test setup or expectations after maintained changes: mandatory composition dialect validation, fail-closed approval behavior, symlink alias handling, and runtime exec-deny rule selection.
- Security/lifecycle failures requiring individual triage: cgroup cleanup and nethelper paths, detached supervisor aggregation, composition cleanup, wrapper setup, and shell-shim behavior.

Failing packages were `cmd/agentsh-shell-shim`, `cmd/agentsh-unixwrap`, `internal/api`, `internal/cli`, `internal/config`, `internal/netmonitor`, `internal/netmonitor/unix`, `internal/ocsf`, `internal/pkgcheck/provider`, `internal/pkgcheck/resolver`, `internal/platform/fuse`, `internal/policy`, `internal/policy/envshim`, `internal/shim`, `internal/shim/kernelinstall`, `internal/store/watchtower/transport`, and `internal/stub`.

Most previously unselected domains did execute successfully, including PostgreSQL classification/policy/proxy tests, MCP inspection, proxy and secret-provider tests, ptrace tests, package and skill checks, most stores and Watchtower/WAL tests, platform-neutral and platform-stub tests, and public `pkg/` libraries.

## Iteration notes

- Record and classify every initial failure rather than weakening the suite implicitly.
- Do not choose coverage or mutation thresholds until baseline data is available.
- Tool selection should be validated against Go 1.25, cgo, build tags, and Nix packaging before adoption.
- This document should be updated as experiments establish runtime, signal quality, false-positive rate, and maintenance cost.
