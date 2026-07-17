# Make project policy overlays precede generic fallback approvals

## Status
Implemented on feature branches; awaiting deployment validation on a fresh supervised FPGA session.

## Priority
High. Project overlays load successfully but cannot provide their intended low-noise allow/deny/approval behavior under realistic supervised policies. This also weakens overlay deny rules into generic approval prompts.

## Implementation status

- AgentSH `eb57bd87` adds an explicit trusted-base `project_overlay_boundary`, preserves deterministic multi-overlay ordering, rejects untrusted/nested boundaries, and adds realistic first-match regression coverage.
- The same AgentSH commit makes custom command/context YAML decoding reject unknown fields without breaking aliases or merge keys, and restores the existing command-rule `timeout` schema.
- `nix-config` `3d9168c` marks the supervised file/command/network fallbacks, the autonomous command/network fallbacks, and the manual-agent network fallback; it pins AgentSH `eb57bd87`.
- AgentSH focused unit/format checks and the aarch64-linux package build passed.
- The downstream aarch64-linux boundary check validates all three generated policies with the pinned AgentSH binary and proves each family has exactly the intended boundary. The `pi-supervised` and `pi-auto` packages build, and the `theo@rose` Home Manager configuration evaluates.
- The equivalent x86_64-linux check was evaluated but could not be built from the aarch64-linux validation host because that Nix daemon had no x86_64-linux builder configured; no source/test failure occurred.

Remaining validation is operational: deploy the pinned revisions, start a new session so the overlay is reloaded, and repeat the non-destructive Xilinx/Vivado probes. The issue should move to `issues/resolved/` only after those probes resolve through the project rules rather than generic fallbacks.

## Problem

AgentSH policies are first-match. `MergePolicyOverlays` currently inserts overlay rules only before terminal catch-all **deny** rules. It does not account for broad fallback **approval** rules that appear immediately before those denies.

The downstream `pi-supervised` policy intentionally ends its file rules with:

1. `approve-outside-workspace-writes`;
2. `approve-outside-workspace-reads`;
3. `default-deny-files`.

It ends its command rules with:

1. `approve-unknown-nix-store-executables`;
2. `approve-unknown-executables`.

Consequences:

- overlay file rules are inserted after the broad outside-workspace approval rules, so matching overlay allows and denies are unreachable;
- because `pi-supervised` has no terminal command deny rule, overlay command rules are appended after both unknown-executable approval fallbacks and are likewise unreachable;
- an overlay deny intended to protect a shared path becomes an approval prompt that an operator can accidentally approve;
- an overlay-specific deployment approval still prompts, but through the generic unknown-command rule, losing its intended message, attribution, and scope;
- adding more rules to the overlay cannot fix the behavior.

## Observed reproduction

A fresh supervised session was started at the umbrella FPGA workspace with the project overlay `doctor-xilinx-build-sim`. The overlay contains, among other rules:

- allow read/execute for `/share/xilinx/Vivado/2022.2` and `/share/xilinx/2025.1`;
- allow the `vivado` frontend and nested Nix-store build helpers;
- deny writes under `/share/xilinx/**`;
- approval-gate hardware programming/deployment commands.

Despite the matching allow rules, AgentSH requested approvals with these base-policy rules:

```text
path: /share/xilinx/Vivado/2022.2
operation: open/read
rule: approve-outside-workspace-reads
```

```text
path: /share/xilinx/2025.1
operation: open/read
rule: approve-outside-workspace-reads
```

The resolved Nix-store Vivado wrapper likewise prompted through:

```text
command: /nix/store/...-vivado/bin/vivado
rule: approve-unknown-nix-store-executables
```

A separate prompt for `/home/theo/.config-rose/nix/nix.conf` is not evidence for this defect: that file may contain access tokens or `netrc-file` configuration and is intentionally handled as a sensitive XDG/Nix policy concern downstream.

Reproductions should confirm session metadata contains the expected `project_policy_overlay_names` before assigning a failure to merge precedence.

## Original source findings

`internal/policy/overlay.go` currently uses:

- `insertFileRulesBeforeTerminalDeny`;
- `insertCommandRulesBeforeTerminalDeny`;
- equivalent helpers for network, Unix-socket, and signal rules.

`isTerminalFileDeny` recognizes only a deny named `default-deny*` or an equivalent catch-all deny. It does not recognize broad catch-all approvals.

`isTerminalCommandDeny` likewise recognizes only terminal denies. When a base policy uses an explicit catch-all approval rather than a terminal command deny, added command rules are appended after it.

The existing `TestMergePolicyOverlaysOrdering` fixture contains an explicit sensitive deny followed directly by a terminal deny. It does not model the supervised fallback-approval rules, so the shadowing behavior is not covered.

## Desired semantics

A merged policy should preserve this effective precedence:

1. trusted base-policy guardrails that overlays must not weaken, including explicit sensitive denies, redirects, and specific approval gates;
2. ordinary trusted base rules that already resolve an operation;
3. validated project-overlay rules;
4. generic base fallback approvals such as outside-workspace or unknown-executable handling;
5. terminal/default denies.

In particular:

- a project allow for a selected external tool path must beat the generic outside-workspace read approval;
- a project deny for writes to that path must beat the generic outside-workspace write approval;
- a project allow for a known Nix-store wrapper must beat `approve-unknown-nix-store-executables`;
- a project-specific deployment approval must beat the generic unknown-executable approval;
- explicit base credential, privilege, and other security-sensitive rules must still win over project overlay rules.

Overlay files must remain unable to alter top-level resources, environment policy, audit settings, providers, or other fields excluded by `PolicyOverlay`.

## Proposed direction

Introduce an explicit notion of a fallback rule or overlay merge anchor instead of relying only on terminal-deny detection.

Possible designs include:

- a validated `fallback` marker on trusted base-policy rules;
- a policy-level overlay insertion anchor;
- a separate evaluation phase that consults project overlays only when trusted base evaluation reaches a marked fallback.

The mechanism must account for scoped fallbacks such as unknown Nix-store executables, not only completely matcherless command rules. Avoid coupling generic AgentSH code solely to downstream rule names such as `approve-outside-workspace-reads`.

Whichever representation is chosen, loading and merging must remain deterministic, explicit base deny precedence must remain intact, and effective rule attribution must identify the overlay rule that actually decided the operation.

## Regression coverage

Extend the focused Nix-backed policy checks with realistic first-match fixtures.

### File rules

- base explicit sensitive deny + overlay broad allow: base deny wins;
- base specific credential approval + overlay broad allow: base approval wins;
- overlay selected-path allow + base outside-read fallback approval: overlay allow wins;
- overlay selected-path write deny + base outside-write fallback approval: overlay deny wins;
- unmatched path still reaches the base fallback approval;
- unmatched operation still reaches the terminal deny where applicable.

### Command rules

- base explicit privilege/deployment approval + overlay broad command allow: base approval wins;
- overlay known Nix-store executable allow + base unknown-Nix-store fallback approval: overlay allow wins;
- overlay project-specific deployment approval + base generic unknown-executable approval: overlay approval wins and retains its message/rule identity;
- unmatched Nix-store and non-store executables still reach their respective base fallbacks.

### Integration

- exercise the generated downstream `pi-supervised` rule ordering, not only a synthetic terminal-deny policy;
- verify `pi-autonomous` behavior does not regress;
- verify overlay path/name/effective-policy hash metadata remains deterministic;
- verify malformed, denied, or unapproved overlays still fail closed according to configuration.

Do not use live Xilinx tools in deterministic tests. Millisecond-scale/synthetic path and executable fixtures are sufficient; retain the Rose FPGA workflow as a deployment smoke test.

## Acceptance criteria

- A loaded project allow for `/share/xilinx/Vivado/2022.2/**` resolves as that overlay allow rather than `approve-outside-workspace-reads`.
- A loaded project deny for `/share/xilinx/**` writes resolves as that deny rather than an outside-workspace approval.
- A loaded project allow for a known Vivado Nix-store wrapper resolves before the unknown-Nix-store approval fallback.
- An unmatched outside path or executable retains current supervised approval behavior.
- Explicit sensitive base rules remain non-overridable by project overlays.
- Focused Nix checks cover file and command fallback precedence.

## Downstream context

- `nix-config/issues/agentsh-supervised-sandbox-limitations-master.md`
- `nix-config/issues/pi-supervised-ssh-and-xdg-read-policy.md`
- draft reproduction overlay: `nix-config/issues/plans/doctor-xilinx-build-sim-overlay.yaml`
