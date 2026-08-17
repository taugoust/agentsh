# Suppress approvals for securely confirmed absent read-only paths

## Status
Open.

## Problem
Linux file mediation receives seccomp user notifications before the kernel performs normal pathname lookup. When policy would require approval, optional discovery probes such as `stat`, `access`, `readlink`, or a read-only `open` can therefore create an interactive approval before the kernel has a chance to return `ENOENT`.

This affects generic tool behavior, not just one caller. Known examples include curl and SQLite startup files, direnv/nix-direnv optional files, and ancestor `.envrc` discovery. Missing candidates should behave like ordinary missing files rather than becoming authorization decisions.

This must not be fixed with per-path deny rules, a blanket home-directory allow, or tool-specific policy exceptions. Those approaches either change filesystem semantics, weaken policy, or require an unbounded inventory of implicit filenames.

## Current architecture
Relevant implementation points:

- `internal/netmonitor/unix/handler.go` resolves syscall arguments and calls `FileHandler.Handle` from both `handleFileNotification` and `handleFileNotificationEmulated`.
- `internal/netmonitor/unix/file_syscalls.go` already classifies read-only file operations with `isReadOnlyFileOp` and parses `openat`, `openat2`, metadata, and legacy syscall arguments.
- `internal/api/file_monitor_linux.go` currently performs the blocking approval inside `filePolicyEngineWrapper.CheckFile`.
- `internal/netmonitor/unix/handler.go` has an exec-only precedent in `execPathMissing`: missing executable candidates are continued so the kernel can return `ENOENT`.
- Seccomp notification responses can complete a syscall with a selected errno rather than using `CONTINUE`.

The exec precedent cannot simply be copied for file reads. Continuing a read after an absence check would permit a file created between the check and continuation to be read without policy approval.

## Required semantics
For a securely confirmed absent, non-mutating target, AgentSH should complete the notification with the tracee's natural `ENOENT` result without creating a pending approval.

The following invariants are mandatory:

1. Never suppress policy for an operation that can mutate the filesystem. This includes write-capable opens, `O_CREAT`, `O_TRUNC`, `O_TMPFILE`, mkdir, unlink, rename destinations, links, ownership changes, and mode changes.
2. After classifying a target as absent, return `ENOENT` directly. Do not send `CONTINUE`; direct completion makes a create-between-check-and-response race conservative—the tracee still receives `ENOENT` and gains no access.
3. Do not equate lookup failure with absence. Inaccessible parents, invalid syscall arguments, unsupported resolution flags, namespace disagreement, stale tracees, and probe failures must remain distinct from confirmed `ENOENT`.
4. Preserve final-symlink semantics. `AT_SYMLINK_NOFOLLOW`, `O_NOFOLLOW`, dangling links, and `readlinkat` cannot all use the same `stat` probe.
5. Resolve relative paths according to the original `AT_FDCWD` or directory-fd context. A cleaned absolute string alone is not an exact substitute for a live dirfd.
6. The probe must use the tracee's mount namespace and filesystem credentials. A supervisor-root `os.Stat("/proc/<pid>/root/...")` is not sufficient as the final design because it can see through permissions that would produce `EACCES` for the tracee.
7. A suppressed probe may produce a bounded audit record, but it must not create an approval request or be represented as a policy denial.

## Proposed decision flow
Avoid probing every allowed file access. Split file-policy evaluation from the blocking approval step and use this sequence:

1. Parse and validate the seccomp notification and resolve its policy path as today.
2. Obtain the non-blocking policy decision.
3. Continue immediately for unconditional allows and enforce explicit denies normally.
4. Only when the effective decision would require interactive approval, classify whether the original read-only lookup is securely absent.
5. On confirmed `ENOENT`, revalidate the notification ID and respond with `ENOENT` without entering the approval manager.
6. On existing, inaccessible, or unknown results, retain normal approval/fail-closed behavior.
7. If approval succeeds, preserve the existing enforcement path; absence suppression must not broaden access.

This likely requires refactoring `filePolicyEngineWrapper.CheckFile`, because it currently waits for approval before the syscall handler has enough control to perform the absent-path short circuit. The policy adapter should expose a raw decision and a separate approval resolution operation, or the syscall handler should receive an approval-capable collaborator after probing.

## Tracee-context probe design
The production classifier should use a small Linux-only probe broker/helper rather than performing lookup with supervisor credentials.

The helper must:

- operate in the tracee's mount namespace;
- use the tracee's filesystem UID, GID, and supplementary groups;
- accept the operation's lookup semantics, pathname, flags, and an equivalent cwd/dirfd reference;
- perform a non-mutating lookup that cannot block on FIFOs or open devices merely to establish existence;
- return a typed result such as `exists`, `absent`, `inaccessible`, `not-directory`, `symlink-loop`, `invalid`, `stale`, or `unknown`;
- never return file contents or other secret-bearing data to the supervisor.

A persistent per-session broker is preferable to spawning a process for every notification, but its namespace, credential, and dirfd assumptions must be validated for descendant processes. For `AT_FDCWD` and directory-relative operations, use stable duplicated directory handles where available rather than a racy textual cwd. If exact semantics cannot be reproduced for a syscall/flag combination, classify it as unknown and retain current policy handling.

A limited prototype may use the existing `/proc/<pid>/root` pattern to validate the notification flow, but it must not be declared complete until permission, namespace, dirfd, and symlink tests pass.

## Initial syscall scope
Start with operations that are inherently read-only or whose flags prove that they are read-only:

- `open`, `openat`, and `openat2` without write/create/truncate/append/tmpfile behavior;
- `statx` and `newfstatat`;
- `faccessat` and `faccessat2`;
- `readlinkat`;
- intercepted legacy equivalents on supported architectures.

Explicitly handle or reject `AT_EMPTY_PATH`, `AT_SYMLINK_NOFOLLOW`, `AT_EACCESS`, `O_PATH`, `O_NOFOLLOW`, and `openat2` `RESOLVE_*` combinations. Mutating operations are out of scope even when their destination is currently absent.

## Seccomp response behavior
Add a response helper named for syscall error completion rather than reusing policy-denial terminology, even if it uses the same underlying ioctl fields. For example:

```go
func NotifRespondErrno(fd int, id uint64, errno int32) error
```

For confirmed absence it should return `-ENOENT` to the tracee with no `CONTINUE` flag. Notification-ID validation should bracket expensive probing and approval work consistently with the existing emulated handler. A stale notification is lifecycle cleanup, not path absence.

## Security and race analysis
The key race is:

1. helper confirms that a read target is absent;
2. another process creates a sensitive file at that pathname;
3. AgentSH responds to the pending notification.

Returning `ENOENT` directly is safe: the original tracee never executes the lookup and cannot read the newly created file. Continuing to the kernel would be unsafe.

The opposite race—an existing file disappears after classification—can still lead to an unnecessary approval, but it does not broaden access. This can be optimized later and is preferable to guessing absence.

Successful read-only open emulation with a retained descriptor and `SECCOMP_IOCTL_NOTIF_ADDFD` could eventually eliminate the existing-path check/use race as a separate hardening step. It is not required merely to suppress confirmed-absent probes and must not delay the conservative `ENOENT` path.

## Observability
Record counters and structured debug metadata without logging contents:

- syscall and operation class;
- result classification;
- whether approval was suppressed;
- backend and session identifier;
- reason an operation remained unknown.

Do not log file contents, curl headers, cookies, tokens, environment secrets, or data returned by `readlinkat`.

## Acceptance criteria
- Missing read-only open/stat/access/readlink probes return `ENOENT` without a pending approval.
- Existing paths still receive their configured allow, deny, or approval decision.
- Missing `O_CREAT` and all other mutations remain subject to normal policy.
- A file created after confirmed absence but before notification response is not opened; the tracee receives `ENOENT`.
- Tests distinguish dangling symlinks, no-follow operations, inaccessible parents, non-directory ancestors, stale notifications, relative cwd paths, and directory-fd paths.
- Tests cover tracees whose mount namespace and effective filesystem credentials differ from the supervisor.
- Unsupported or ambiguous syscall forms fail closed and do not get guessed as absent.
- Suppressed probes do not populate the approval queue and do not poison approval-scope caches.
- Regression smokes cover direct sessions, detached supervisors, SSH, and the Virby deployment topology.

## Related documentation
- `plans/dynamic-path-prompts.md`
- `docs/superpowers/specs/2026-03-20-seccomp-notify-file-enforcement-design.md`
- `docs/superpowers/plans/2026-03-20-seccomp-notify-file-enforcement.md`
- `internal/netmonitor/unix/handler.go`
- `internal/netmonitor/unix/file_syscalls.go`
