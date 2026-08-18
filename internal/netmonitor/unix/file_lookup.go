package unix

import "context"

// FileLookupRequest is the exact, non-content context needed to reproduce a
// pathname lookup. ResolvedPath is only a policy/magic-link/FUSE guard;
// RawPath and DirFD remain authoritative for the broker lookup.
type FileLookupRequest struct {
	TID          int
	Syscall      int32
	DirFD        int32
	PathPtr      uint64 // supervisor-only revalidation pointer; never sent to the broker
	RawPath      string
	ResolvedPath string

	OpenFlags    uint64
	OpenMode     uint64
	ResolveFlags uint64

	LookupFlags uint32
	StatMask    uint32
	AccessMode  uint32
	AccessFlags uint32

	ReadlinkBufferLen uint64

	// openat2 is extensible by size. OpenHowParsed confirms that the complete
	// supplied object was read, is at least version 0, is bounded, and has only
	// zero bytes beyond the known version. OpenHowSize retains the exact size
	// passed by the tracee; OpenHowVersion identifies the understood prefix.
	OpenHowSize              uint64
	OpenHowVersion           uint32
	OpenHowParsed            bool
	OpenHowTrailingBytesZero bool

	// A Go string alone cannot prove that the tracee supplied a complete Linux
	// pathname. This bit is set only by the strict pathname reader.
	PathnameNULTerminated bool
}

// LookupClass is a bounded lookup outcome. Only LookupAbsent is eligible for
// future ENOENT completion; every infrastructure or context failure is
// represented as unknown/unavailable instead of being guessed absent.
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

// LookupReason is deliberately bounded so broker failures cannot turn helper
// output, paths, labels, or other sensitive values into logs or events.
type LookupReason string

const (
	LookupReasonNone                 LookupReason = "none"
	LookupReasonUnavailable          LookupReason = "unavailable"
	LookupReasonIneligible           LookupReason = "ineligible"
	LookupReasonAdmission            LookupReason = "admission"
	LookupReasonTimeout              LookupReason = "timeout"
	LookupReasonProtocol             LookupReason = "protocol"
	LookupReasonWorkerCrash          LookupReason = "worker_crash"
	LookupReasonWorkerUnavailable    LookupReason = "worker_unavailable"
	LookupReasonTaskStale            LookupReason = "task_stale"
	LookupReasonLineageMismatch      LookupReason = "lineage_mismatch"
	LookupReasonNamespaceMismatch    LookupReason = "namespace_mismatch"
	LookupReasonRootMismatch         LookupReason = "root_mismatch"
	LookupReasonCredentialMismatch   LookupReason = "credential_mismatch"
	LookupReasonCapabilityMismatch   LookupReason = "capability_mismatch"
	LookupReasonSecurityLabel        LookupReason = "security_label_mismatch"
	LookupReasonCgroupMismatch       LookupReason = "cgroup_mismatch"
	LookupReasonContextUnavailable   LookupReason = "context_unavailable"
	LookupReasonPIDSensitiveLSM      LookupReason = "pid_sensitive_lsm"
	LookupReasonFUSE                 LookupReason = "fuse"
	LookupReasonMagicLink            LookupReason = "magic_link"
	LookupReasonDirectoryUnavailable LookupReason = "directory_unavailable"
	LookupReasonSymlinkContext       LookupReason = "symlink_context"
	LookupReasonErrno                LookupReason = "errno"
)

// FileLookupResult contains no file contents or symlink target. Errno is the
// worker's raw positive errno when one was produced.
type FileLookupResult struct {
	Class  LookupClass
	Errno  int32
	Reason LookupReason
}

// FileLookupProbe classifies one eligible lookup. Implementations must return
// LookupUnknown on infrastructure failure; callers must never infer absence
// from an error, timeout, closed endpoint, or zero value.
type FileLookupProbe interface {
	ProbeFileLookup(context.Context, FileLookupRequest) FileLookupResult
}

// FileLookupBroker is a session-bound probe endpoint with explicit lifecycle.
type FileLookupBroker interface {
	FileLookupProbe
	Close() error
}

func unknownFileLookup(reason LookupReason) FileLookupResult {
	if reason == "" {
		reason = LookupReasonUnavailable
	}
	return FileLookupResult{Class: LookupUnknown, Reason: reason}
}
