# Missing read probes: implementation plan

## Goal

When a read-only file syscall would otherwise create an interactive approval, reproduce the original lookup in the tracee's security context. If and only if that lookup is securely confirmed absent, complete the seccomp notification with `ENOENT` without creating or caching an approval.

This is Linux/seccomp-only. Other platforms and enforcement backends retain their current behavior.

## Security decisions

1. **Return `ENOENT`; never `CONTINUE`, for confirmed absence.** A concurrent create can then only cause a conservative false `ENOENT`, never unapproved access.
2. **Use a tracee-lineage broker, not supervisor `/proc/<pid>/root` probing.** A supervisor-spawned helper cannot reproduce Landlock, AppArmor/SELinux transitions, cgroup/BPF LSM state, the tracee root, or FUSE caller identity.
3. **Probe only genuinely unresolved approvals.** Unconditional allow, explicit deny, cached allow/deny, unsupported approval scope, and audit-only/FUSE delegation do not invoke the broker.
4. **Positive eligibility allowlist.** No mutating syscall or ambiguous argument form can reach absence suppression.
5. **Ambiguity preserves current handling.** Invalid arguments, stale tasks, context mismatch, helper timeout, namespace/root/credential/LSM disagreement, proc magic links, and unsupported flags classify as non-absent and retain normal policy behavior. Stale notifications are lifecycle cleanup and never create an approval.
6. **All policy obligations survive.** Visible paths, second paths, and composition source paths remain independent obligations with deny dominance. Existing operations must resolve every unresolved obligation; the refactor must not collapse them into one “final” approval.

## Architecture

```text
agentsh-unixwrap
  -> prepare final mount/user/root + Landlock rules
  -> remain as the trusted broker parent on one locked OS thread
  -> enter final Landlock/credential/cgroup context
  -> fork the payload child, which alone installs user-notify seccomp and execs
  -> send the broker endpoint + child notify FD in one authenticated handoff

supervisor notify loop
  -> parse original syscall and policy path
  -> FileHandler.Prepare: raw policy + nonblocking scope-cache checks
       allow / deny / cached result -> existing response path
       unresolved obligation(s)    -> lookup broker
          confirmed ENOENT -> revalidate -> complete with -ENOENT
          other result      -> resolve every approval obligation -> existing path
```

### Why the broker is wrapper-side

The broker must inherit the payload's unforgeable filesystem context rather than trying to reconstruct it later:

- mount and user namespace;
- root and mount topology;
- Landlock domain and other inherited LSM state;
- cgroup/BPF attachments;
- UID/GID/fsuid/fsgid, supplementary groups, capability sets, securebits, and `no_new_privs`.

Before every probe it compares its baseline with the target task. If exec transitions or a descendant changes root, mount/user namespace, credentials, groups, capabilities, security label, or other validated context, it returns `unknown`. The initial implementation does not `setns`, `chroot`, or elevate privileges on behalf of changed descendants.

Use the same topology for ordinary and command-jail execution: the trusted wrapper remains as the payload's parent/broker instead of `exec`ing into the payload. It stays on the exact locked OS thread on which Landlock and final credentials were applied. It forks one payload child; only that child installs the user-notify filter and execs. The parent runs the broker loop, forwards signals, reaps only the exact payload child, returns its exit status, and exits with it. This extends the parent pattern already used by `runCommandJailStage` to the ordinary path and avoids making a hidden broker waitable by untrusted payload code.

Attach the wrapper/broker PID to the command cgroup before releasing the fork barrier so the payload child and every lookup worker inherit the exact cgroup/BPF context. Include broker/worker reserve in `pids.max` accounting. The supervisor binds the authenticated broker PID, payload PID, notify FD, and session lifecycle; cancellation kills the whole cgroup and closes the broker endpoint.

The broker endpoint is a private inherited Unix socket. Extend the existing SCM_RIGHTS handoff with a typed capability/version frame; do not expose a filesystem socket. Do not advertise file-probe readiness until the parent and child context-parity handshake succeeds.

Freeze the inherited security context when probing is enabled: the payload seccomp filter must deny subsequent Landlock-domain mutation syscalls. Compare observable AppArmor/SELinux labels after exec and classify mismatches as unknown. If an active BPF LSM or another configured LSM can make pathname decisions by caller PID and parity cannot be attested, mark the broker unsupported for that session. This is an explicit supported-context boundary, not a best-effort check.

## Broker safety model

Keep broker control on the wrapper's Landlock-restricted locked OS thread. Perform each actual lookup in a tiny Linux-only native worker (C is preferred to avoid Go runtime threads), built statically and pinned by fd. The wrapper forks/executes that worker only after validating the request; the worker inherits the exact parent context and never performs namespace or credential elevation.

Before accepting requests it must:

- set `PR_SET_DUMPABLE=0` before holding sensitive descriptors;
- set `PR_SET_PDEATHSIG=SIGKILL`;
- clear environment, ambient capabilities, and unnecessary bounding capabilities;
- close every descriptor except the authenticated supervisor channel and broker control descriptors;
- use safe stdio (`/dev/null` or closed as appropriate);
- set and verify `no_new_privs`;
- install a minimal seccomp allowlist before serving requests;
- accept a versioned fixed-size/bounded binary protocol, never JSON or shell arguments;
- return only a result enum, raw errno, and bounded reason enum—never contents or symlink targets.

Pin the trusted native worker code by descriptor before applying Landlock and execute `/proc/self/fd/<N>`, following `internal/composition/broker_linux.go`; do not discover it through PATH or rely only on a sibling pathname. Likewise, open every broker-owned proc descriptor needed for later parity checks before Landlock where possible. If the finalized Landlock rules do not permit a required check and no pinned descriptor can provide it, disable suppression for that session rather than weakening the rules.

Use one broker per wrapper/session. The broker forks at most one lookup worker at a time. The coordinator applies a short deadline. On timeout, kill/reap the worker; if it is uninterruptibly blocked, disable probing for that broker and permit at most that one stuck worker until cgroup/session teardown. Add per-session and global admission bounds so probe floods cannot accumulate processes or stall the listener indefinitely.

## Typed lookup request/result

Add a shared protocol and Go-side types:

```go
type FileLookupRequest struct {
    TID              int
    Syscall          int32
    DirFD            int32
    RawPath          string
    OpenFlags        uint64
    ResolveFlags     uint64
    LookupFlags      uint32
    StatMask         uint32
    AccessMode       uint32
    AccessFlags      uint32
    ReadlinkBufferLen uint64
}

type LookupClass string
const (
    LookupExists       LookupClass = "exists"
    LookupAbsent       LookupClass = "absent"
    LookupInaccessible LookupClass = "inaccessible"
    LookupNotDirectory LookupClass = "not_directory"
    LookupSymlinkLoop  LookupClass = "symlink_loop"
    LookupInvalid      LookupClass = "invalid"
    LookupStale        LookupClass = "stale"
    LookupUnknown      LookupClass = "unknown"
)
```

Only the lookup worker's raw `ENOENT` maps to `LookupAbsent`. Keep `EACCES/EPERM`, `ENOTDIR`, `ELOOP`, `EINVAL`, `EBADF`, `ESTALE`, timeout/crash/protocol failures, and unsupported contexts distinct.

The supervisor must read a confirmed NUL-terminated pathname. Fix the current string-reader ambiguity so a short/page-boundary/4096-byte non-NUL read cannot become a truncated probe path.

## Exact-context validation

At broker creation, record a baseline fingerprint and attest that the payload child inherited it before exec. Before and after each lookup, compare the target with the broker using pinned proc task descriptors rather than independent PID path opens. Supported sessions require frozen Landlock state, no active unmodelled PID-sensitive BPF LSM, and readable/attestable security labels; otherwise probing is disabled:

- PID/TID identity and start time;
- user, mount, and PID namespace identities;
- root mount ID/inode and root identity;
- real/effective/saved/fs UID/GID, supplementary groups;
- effective/permitted/inheritable/ambient capabilities, securebits, `no_new_privs`;
- available LSM security label (`/proc/<tid>/attr/current`) and Landlock state where observable;
- cgroup identity relevant to BPF LSM;
- FUSE-backed lookup detection.

Use `NSpid` translation for command-jail PID namespaces. Any unavailable or mismatched field returns `unknown`. Do not probe FUSE-backed paths initially because the daemon observes the broker PID rather than the tracee PID. Do not probe `/proc/self`, `/proc/thread-self`, `/proc/<pid>/fd`, `/dev/fd`, or related magic-link forms initially; existing tracee-aware policy alias handling remains, but absence classification returns `unknown`.

For a relative request, the broker opens the exact target task's `cwd` or directory fd through its private proc view and pins an `O_PATH` base handle before lookup. If this cannot be done under the inherited security domain, return `unknown`. Absolute paths use the broker's inherited root. Validate same-mount-namespace/different-chroot as a mismatch rather than assuming mount namespace equality implies root equality.

## Lookup semantics

### Eligible initial forms

- `open`, `openat`: read-only access only. Reject write access, `O_CREAT`, `O_TRUNC`, `O_APPEND`, `O_TMPFILE`, unknown flags, and invalid access-mode combinations. For ordinary follow-final-symlink opens, use `O_PATH|O_CLOEXEC` plus `O_DIRECTORY` as applicable. For `O_PATH`, preserve its exact lookup flags. Non-`O_PATH` `O_NOFOLLOW` is initially `unknown` because adding `O_PATH` changes `ELOOP` semantics.
- `openat2`: require a fully readable, bounded, known `open_how`; reject nonzero mode without create/tmpfile, all mutations, unknown flags, unknown/future `RESOLVE_*` bits, `RESOLVE_IN_ROOT`, and non-`O_PATH` `O_NOFOLLOW`. Use `openat2` with `O_PATH|O_CLOEXEC`, preserving the remaining supported resolution flags. Any semantic doubt returns `unknown`.
- `statx`, `newfstatat`, and supported legacy stat/lstat forms: issue the equivalent metadata syscall with original supported flags and stat mask. Preserve `AT_SYMLINK_NOFOLLOW`.
- `faccessat`, `faccessat2`, and legacy access: preserve access mode and supported `AT_EACCESS` semantics. Permission failure is inaccessible, never absent.
- `readlinkat` and supported legacy readlink: require a non-empty pathname and a valid nonzero output-buffer length, then use a no-follow metadata lookup. Empty-path `readlinkat` is descriptor-oriented and initially ineligible. Existing regular files and symlinks—including dangling symlinks—classify as existing; no target bytes are read.

### Explicitly ineligible initially

- `AT_EMPTY_PATH`, empty-path `readlinkat`, and `openat2 RESOLVE_IN_ROOT`;
- proc/dev magic links;
- unsupported legacy architecture forms;
- unknown or invalid `open_how` versions/flags;
- any mutation, dual-path mutation, ownership/mode change, or create-like operation;
- non-`O_PATH` `O_NOFOLLOW` opens;
- context-changing descendants the broker cannot prove equivalent.

“Ineligible” means normal policy/approval handling, not allow or deny.

## Implementation sequence

### 1. Refactor policy evaluation without weakening obligations

Files:

- `internal/netmonitor/unix/file_handler.go`
- `internal/api/file_monitor_linux.go`
- tests in both packages

Changes:

- Make `filePolicyEngineWrapper.CheckFile` return raw policy plus a nonblocking scoped-cache result. It must never call `RequestApproval`.
- Add `FileApprovalResolver.ResolveFileApproval`, containing the current scope construction, command identity, request fields, cancellation, and `RequestApproval` behavior.
- Introduce `PreparedFileDecision` with a list of policy obligations. Each obligation retains target, operation, raw decision, rule/message, cache outcome, and composition/source attribution.
- `FileHandler.Prepare` performs normalization, composition/source evaluation, FUSE delegation, loader-safe overrides, deny dominance, and cached checks only.
- `FileHandler.Resolve` requests every unresolved obligation and denies if any resolution fails.
- Retain `Handle` as a compatibility wrapper over Prepare+Resolve.
- Add an approvals-manager operation that atomically checks the exact scoped cache and registers a pending request under the same manager lock. A separate `CheckScoped` followed by insertion is not sufficient. Use this operation from `Resolve`.
- Bind resolution to a notification-liveness context. Revalidate before every obligation; poll/cancel while waiting; once staleness is observed, cancel and remove any request registered in the check-to-kernel transition window and never enqueue later obligations. The achievable invariant is that no stale-notification request remains pending, even if a request existed briefly before kernel staleness became observable.

Tests must cover mixed allow/deny/approve/cached outcomes across visible path, second path, and composition source; prove Prepare cannot populate pending approvals or scoped caches; and prove Resolve preserves existing scope semantics.

### 2. Parse complete syscall semantics

Files:

- `internal/netmonitor/unix/file_syscalls.go`
- `internal/netmonitor/unix/execve_reader.go` or a dedicated pathname reader
- legacy syscall files and tests

Changes:

- Carry access mode separately from flags (`faccessat` is currently conflated).
- Preserve statx mask, readlink buffer length, `open_how.resolve`, and exact `how_size`/trailing-byte validation.
- Require confirmed pathname NUL termination.
- Add `eligibleMissingLookup` as a positive syscall/flag/context allowlist.
- Add table tests for all accepted/rejected combinations, including page-boundary strings, `O_PATH`, `O_NOFOLLOW`, every write/create flag, `AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW`, `AT_EACCESS`, invalid stat masks, zero readlink length, and unknown `RESOLVE_*` bits.

### 3. Add neutral syscall-error completion

Files:

- `internal/netmonitor/unix/addfd_linux.go`
- tests

Add `NotifRespondErrno(fd, id, errno)` with positive-errno validation and no `CONTINUE`. Keep `NotifRespondDeny` as a compatibility wrapper if useful. Unit-test the ioctl response layout.

### 4. Implement and hand off the lineage broker

Files likely affected:

- new broker protocol/native source under `cmd/agentsh-file-lookup-broker/`
- `cmd/agentsh-unixwrap/main.go`
- `cmd/agentsh-unixwrap/command_jail_linux.go`
- wrapper handoff code in `internal/api/notify_linux.go` and `internal/api/wrap_linux.go`
- `internal/netmonitor/unix/file_lookup_broker_linux.go`
- non-Linux stubs
- packaging: `flake.nix`, `.goreleaser.yml`, container/package definitions that enumerate trusted binaries

Changes:

- convert ordinary execution to the same trusted-parent/payload-child topology as command jail, with exact-child wait/signal/exit propagation;
- establish the broker on the locked Landlock/credential thread before forking the payload and pin worker/proc descriptors before restriction;
- attach the trusted parent to the command cgroup before child release and reserve broker/worker PIDs in limits;
- deny post-fork Landlock mutation in the payload filter and define explicit unsupported behavior for unmodelled PID-sensitive LSMs;
- send its endpoint in a versioned SCM_RIGHTS handoff and fail closed to “probe unavailable,” not session startup failure, if optional probing cannot initialize;
- authenticate exact wrapper/broker lineage and bind broker lifecycle to session cancellation/cgroup teardown;
- implement bounded protocol, context fingerprinting, worker timeout/admission, and typed results;
- pin native broker code by fd and verify static linkage in every Linux package architecture.

### 5. Integrate with one common file-notification pipeline

Files:

- `internal/netmonitor/unix/handler.go`
- `internal/netmonitor/unix/file_handler.go`
- tests

Deduplicate parsing and decision flow used by normal and emulated handlers.

For eligible unresolved approval obligations:

1. Validate notification ID; `ENOENT` means stale—return without response or approval.
2. Pin task identity and read the exact raw pathname/context.
3. Ask the broker to classify.
4. Revalidate task identity, raw pathname, broker context fingerprint, and notification ID.
5. On exact `LookupAbsent`, call `NotifRespondErrno(..., ENOENT)`.
6. Mark suppression only if that response succeeds.
7. On `LookupStale`, return without approval.
8. On every other result, resolve all approval obligations through atomic scope-check-and-register, revalidating before each obligation and cancelling/removing requests when staleness is observed.
9. After each approval and again before AddFD/CONTINUE/error response, validate notification ID.

Inject notification validation/responding, clock/deadline, and broker interfaces so stale and race behavior is deterministic in unit tests.

### 6. Observability without a new event taxonomy

Annotate the existing file event with bounded fields:

- `lookup_probe_backend=tracee_lineage_broker`;
- `lookup_probe_result`;
- bounded `lookup_probe_reason`;
- `approval_suppressed`;
- existing syscall, operation, path, backend, and session metadata.

For successful suppression use `EffectiveAction: "not_found"`; retain the raw approve policy decision, omit approval ID, and never represent it as blocked/denied. Unknown classifications can be debug-logged with bounded enums. Reuse existing event counting rather than adding a new event type unless metrics requirements prove that insufficient; if a new type is added, update event registry, OCSF mapping, sanitization, and exhaustiveness tests together.

Never log helper stderr, contents, symlink targets, environment, curl headers/cookies, or secret-bearing values.

## Test matrix

### Unit/component

- missing eligible open/stat/access/readlink: direct `ENOENT`, zero pending approvals, no scope-cache mutation;
- existing counterparts: every configured obligation still prompts/resolves;
- cached allow/deny: no probe and no new request;
- missing `O_CREAT`, write, truncate, append, tmpfile, mkdir, unlink, rename, link, chmod/chown/mknod: normal policy/approval;
- create after broker says absent but before response: response is still direct `ENOENT`, never CONTINUE/AddFD;
- dangling symlink follow/no-follow/open/readlink/stat matrix;
- inaccessible parent, ENOTDIR ancestor, ELOOP, invalid argument, non-NUL pathname, unsupported flag, broker unavailable/crash/timeout, and stale task never suppress;
- stale notification before probe, after probe, during approval, and before final response never queues a new approval after staleness;
- relative cwd uses pinned target cwd; directory-fd lookup remains tied to the original directory after rename/replacement;
- same mount namespace but different chroot/root returns unknown;
- namespace/root/credential/group/capability/security-label/cgroup mismatch returns unknown;
- proc/dev magic links and FUSE mounts return unknown;
- multiple visible/source obligations retain deny dominance and require all approvals;
- broker flood/timeout/cancellation leaves at most one disabled stuck worker and teardown kills it.

### Privileged NixOS VM

Add `nix/checks/missing-read-probes.nix` and a focused flake output. The VM must not skip:

- real seccomp user notifications and direct `-ENOENT` response;
- tracee mount namespace/root differing from supervisor while broker sees the tracee view;
- tracee fs credentials/groups differing from supervisor;
- Landlock-inaccessible parent remains non-absent;
- command-jail/composition broker initialization and teardown;
- direct and detached supervisors;
- an SSH-launched command path using the same packaged wrapper;
- no pending approval/cache entry for missing probes; existing and mutating cases still prompt;
- create-between-classification-and-response race via a deterministic test hook;
- no orphan broker/worker after normal exit, cancellation, timeout, or detached recovery.

## Nix-native validation gates

Add `checks.<system>.missing-read-probe-tests` for focused Go/native tests and the x86_64-linux VM check. Then run:

1. `nix fmt -- <changed Go/Nix files>`
2. `nix build --no-link .#checks.x86_64-linux.missing-read-probe-tests`
3. `nix build --no-link .#checks.x86_64-linux.approval-regression-tests`
4. `nix build --no-link .#checks.x86_64-linux.go-unit-tests`
5. Linux cross/package checks, including aarch64 static broker packaging
6. Darwin API cross-compile check and non-Linux stubs
7. `nix flake check`

Never invoke `go test` or `go build` directly outside Nix derivations.

## Deployment qualification and repository boundary

After AgentSH checks, deploy locally through the existing `nix-config` input override and reproduce curl/SQLite/direnv optional probes. Confirm missing reads do not appear in the approval queue, existing approved files and missing creates still prompt, event fields are bounded, and repeated direct/detached/SSH cycles clean up brokers.

Virby-specific deployment smoke belongs to `nix-config`. Finish AgentSH first, then ask before modifying that repository.

Finally move `issues/missing-read-probes-prompt-before-enoent.md` to `issues/resolved/`, set `Status` to `Resolved.`, and add a resolution section referencing implementation and qualification commits.

## Planned commit boundaries

1. `Refactor file approvals into prepare and resolve phases`
2. `Preserve exact read lookup syscall context`
3. `Add tracee-lineage file lookup broker`
4. `Suppress approvals for securely absent read probes`
5. `Add missing-read probe VM regression coverage`
6. `Resolve missing read probe approval issue`

Each boundary must pass its focused Nix check. Do not mark the issue resolved until namespace/root/credential/Landlock VM tests and live deployment smoke pass.
