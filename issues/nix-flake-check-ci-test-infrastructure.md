# Add comprehensive `nix flake check` and CI test infrastructure

## Status
Open.

## Problem
AgentSH does not currently have a comprehensive Nix-native test contract suitable for local CI or remote CI.

Current `flake.nix` only defines a narrow `checks.go-unit-tests` derivation that runs a few project-overlay tests:

```sh
go test ./internal/policy -run 'Test(DiscoverProjectOverlays|LoadOverlay|MergePolicyOverlays)'
go test ./internal/config -run 'TestProjectOverlays'
```

Package builds set:

```nix
doCheck = false;
```

because many tests touch kernel/security features such as FUSE, seccomp, eBPF, ptrace, network namespaces, cgroups, and detached supervisor behavior.

As a result, `nix flake check` is not a meaningful regression suite for AgentSH. Important recent areas can regress without being caught:

- detached supervisor lifecycle and metadata discovery;
- Unix supervisor socket transport and timeout behavior;
- approval resolution and cancellation semantics;
- subagent process/runtime/protocol behavior;
- shadow workspace review/accept lifecycle;
- ptrace vs seccomp execve approval behavior;
- regular vs streaming exec runner divergence;
- NixOS module option rendering and generated config shape.

## Evidence / files inspected

- `flake.nix`: `checks.go-unit-tests` only runs two targeted `go test` commands.
- `flake.nix`: main package derivation has `doCheck = false`.
- `flake.nix`: Linux package build has `preBuild` eBPF generation, but test derivation does not build broad packages that import eBPF artifacts.
- Existing known failure class when running broad tests without generated eBPF artifacts:

  ```text
  internal/netmonitor/ebpf/program_linux.go:17:12: pattern connect_bpfel.o: no matching files found
  ```

- Existing issue notes in `issues/` identify areas needing regression coverage:
  - `detached-supervisor-transport-timeout-sprawl.md`
  - `detached-supervisor-metadata-lifecycle.md`
  - `approval-resolution-race-semantics.md`
  - `resolved/subagent-terminal-state-model.md`
  - `resolved/subagent-process-tree-cancellation.md`
  - `shadow-workspace-review-atomicity.md`
  - `exec-runner-duplication-http-stream.md`
  - `ptrace-approve-ux-gap.md`

## Desired CI contract

Make these commands meaningful and documented:

```sh
nix flake check
nix build .#agentsh
nix build .#checks.x86_64-linux.<check-name>
```

Guiding principle: `nix flake check` is all-or-nothing for `checks.<system>.*`. There is no built-in test tier or `--only-fast` flag. Therefore the decision is not primarily "fast vs slow"; it is whether the test fits the pure-derivation model.

Include a test in `checks` when it is:

- deterministic: same inputs produce the same result;
- sandboxable: no live network, real secrets, host hardware, or `--impure` dependency;
- bounded: expensive is acceptable if it is cacheable and not unbounded;
- meaningful under Nix caching: cache hits should represent valid prior results.

Do not put tests in AgentSH `checks` if they depend on a maintainer's real machines, personal network, live SaaS accounts, OAuth state, or secrets. AgentSH is general software; tests for a specific user's MateBook, DOS hosts, Tailscale setup, GitHub login, or SSH agent belong in downstream/private configuration, not this repository.

### 1. Default `nix flake check`: all pure checks for the selected system

Should include all deterministic, sandboxable, bounded checks for the current system, even if some are slow on a cold cache.

Include:

- package build for `packages.${system}.agentsh`;
- formatting/lint checks if available;
- pure Go unit tests that do not require privileged kernel features;
- NixOS module evaluation tests;
- targeted tests for config/policy parsing, approvals manager, session metadata, client/path utilities, and subagent pure parsing/result code;
- deterministic integration tests that can run in the Nix sandbox;
- deterministic NixOS VM tests for Linux/kernel behavior, exposed under Linux `checks`.

### 2. Linux package/import sanity check with generated eBPF artifacts

Ensure broad Linux package import/build checks do not fail due missing generated eBPF object files.

Possible approaches:

- factor eBPF generation into a reusable Nix build phase/helper used by both package and tests;
- add a dedicated check that runs `make -C internal/netmonitor/ebpf clean all` before `go test` packages that import the generated files;
- add build tags or test partitioning so pure tests do not accidentally import missing generated artifacts.

### 3. Targeted non-privileged integration checks

Run end-to-end-ish checks that do not need privileged kernel features, for example:

- detached supervisor start/list/info/destroy using Unix sockets;
- Unix supervisor long-lived streaming request timeout regression;
- approval manager race/cancellation unit tests;
- subagent runtime config parsing and stream result handling with fake child processes;
- shadow workspace diff/accept using temp dirs and `rsync`.

### 4. Linux VM-backed checks

Kernel/security behavior should be tested as deterministic NixOS VM checks under Linux `checks`, not kept out merely because it is slower:

- seccomp execve enforcement;
- ptrace execve enforcement;
- ptrace approval limitations or support;
- FUSE/overlay/shadow workspace behavior where needed;
- cgroups/resource limits;
- eBPF network monitoring;
- network namespace behavior.

Preferred form: NixOS VM tests under `checks.x86_64-linux.integration-*`. Darwin developers can still target those checks explicitly when a Linux builder is configured, e.g.:

```sh
nix build .#checks.x86_64-linux.integration-ptrace-vm
```

### 5. CI matrix documentation

Document the CI contract around pure Nix checks:

```text
nix flake check                                # build every pure check for the current system
nix build .#checks.x86_64-linux.<name>         # target a specific Linux check from another system/builder
nix build .#checks.x86_64-linux.integration-*  # deterministic NixOS VM/kernel integration checks
```

Avoid documenting or implying real-host/personal-environment tests in AgentSH. If downstream users want smoke tests against their own infrastructure, those should live outside AgentSH, e.g. in a private flake or `nix-config`.

## Proposed direction

1. Refactor `flake.nix` checks into named derivations:

   ```text
   checks.<system>.package-build
   checks.<system>.go-unit-fast
   checks.<system>.go-unit-linux-generated
   checks.<system>.nixos-module-eval
   checks.<system>.detached-supervisor-smoke
   checks.<system>.subagent-runtime-smoke
   checks.<system>.integration-seccomp-vm
   checks.<system>.integration-ptrace-vm
   ```

2. Add a clear test partitioning convention:

   - pure, deterministic, bounded tests go under `checks`, regardless of whether they are unit, integration, or NixOS VM tests;
   - platform-specific tests live under the relevant system's `checks` output;
   - Linux privileged/kernel behavior should use deterministic NixOS VM checks where possible;
   - macOS coverage is limited to basic build/pure checks that do not require EndpointSecurity Framework, system extensions, signing workflows, GUI notification behavior, or host-specific setup;
   - impure, flaky, live-network, or secret-dependent tests do not belong in AgentSH `checks`.

3. Make generated eBPF artifacts a first-class Nix build dependency for checks that need them.

4. Add NixOS VM tests for the most important real AgentSH behaviors.

5. Document the intended local and CI commands in `docs/ci-and-releases.md` or similar.

## Rough priority
High.

## Notes
This is infrastructure work, but it should pay for itself quickly: recent fixes around Unix supervisor timeouts, detached sessions, subagents, and approval semantics all need reliable regression coverage before deeper refactors.
