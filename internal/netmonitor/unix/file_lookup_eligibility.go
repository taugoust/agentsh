//go:build linux && cgo

package unix

import (
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// Linux copies at most PATH_MAX bytes, including the terminating NUL, for
	// pathname-taking syscalls. A 4095-byte pathname followed by NUL is valid;
	// 4096 bytes without NUL is not a complete pathname.
	maxTraceePathnameLen = 4096

	openHowSizeVersion0 = 24
	maxOpenHowSize      = 4096

	// RESOLVE_CACHED is part of the Linux openat2 ABI but is not exposed by all
	// x/sys/unix versions supported by AgentSH.
	resolveCached = uint64(0x20)
)

// fileLookupRequest constructs lookup context only after a strict pathname
// read has succeeded.
func (a FileArgs) fileLookupRequest(tid int, nr int32, rawPath, resolvedPath string) FileLookupRequest {
	return FileLookupRequest{
		TID:                      tid,
		Syscall:                  nr,
		DirFD:                    a.Dirfd,
		PathPtr:                  a.PathPtr,
		RawPath:                  rawPath,
		ResolvedPath:             resolvedPath,
		OpenFlags:                a.OpenFlags,
		OpenMode:                 a.OpenMode,
		ResolveFlags:             a.ResolveFlags,
		LookupFlags:              a.LookupFlags,
		StatMask:                 a.StatMask,
		AccessMode:               a.AccessMode,
		AccessFlags:              a.AccessFlags,
		ReadlinkBufferLen:        a.ReadlinkBufferLen,
		OpenHowSize:              a.HowSize,
		OpenHowVersion:           a.HowVersion,
		OpenHowParsed:            a.HowParsed,
		OpenHowTrailingBytesZero: a.HowTrailingBytesZero,
		PathnameNULTerminated:    true,
	}
}

// eligibleMissingLookup is deliberately a positive allowlist. Returning false
// means normal policy/approval handling; it never means allow or deny.
func eligibleMissingLookup(req FileLookupRequest) bool {
	if !eligibleLookupPathContext(req) {
		return false
	}

	switch req.Syscall {
	case unix.SYS_OPENAT:
		return eligibleOpenLookup(req, false)
	case unix.SYS_OPENAT2:
		return eligibleOpenLookup(req, true)
	case unix.SYS_STATX:
		return eligibleStatxLookup(req)
	case unix.SYS_NEWFSTATAT:
		return eligibleNewfstatatLookup(req)
	case unix.SYS_FACCESSAT:
		return eligibleFaccessatLookup(req)
	case unix.SYS_FACCESSAT2:
		return eligibleFaccessat2Lookup(req)
	case unix.SYS_READLINKAT:
		return eligibleReadlinkLookup(req)
	default:
		return eligibleLegacyMissingLookup(req)
	}
}

// EligibleFileLookup reports whether req is in the initial positive lookup
// allowlist. False always means normal policy handling, never allow or deny.
func EligibleFileLookup(req FileLookupRequest) bool {
	return eligibleMissingLookup(req)
}

func eligibleLookupPathContext(req FileLookupRequest) bool {
	if req.TID <= 0 || !req.PathnameNULTerminated || strings.IndexByte(req.RawPath, 0) >= 0 || len(req.RawPath) >= maxTraceePathnameLen {
		return false
	}
	if !filepath.IsAbs(req.RawPath) && req.DirFD < 0 && req.DirFD != int32(unix.AT_FDCWD) {
		return false
	}
	return !isProcDevMagicLinkPath(req.RawPath) && !isProcDevMagicLinkPath(req.ResolvedPath)
}

func eligibleOpenLookup(req FileLookupRequest, openat2 bool) bool {
	if req.LookupFlags != 0 || req.StatMask != 0 || req.AccessMode != 0 || req.AccessFlags != 0 || req.ReadlinkBufferLen != 0 {
		return false
	}

	flags := req.OpenFlags
	if flags&^knownOpenFlagMask() != 0 {
		return false
	}
	if flags&uint64(unix.O_ACCMODE) != uint64(unix.O_RDONLY) {
		return false
	}

	// O_EXCL without O_CREAT has special block-device semantics. It is not a
	// create in that form, but it is intentionally unsupported rather than
	// guessed. The remaining bits are all mutating/create-like.
	mutationFlags := uint64(unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND | unix.O_EXCL)
	mutationFlags |= uint64(unix.O_TMPFILE &^ unix.O_DIRECTORY)
	if flags&mutationFlags != 0 {
		return false
	}
	if flags&uint64(unix.O_NOFOLLOW) != 0 && flags&uint64(unix.O_PATH) == 0 {
		return false
	}

	if !openat2 {
		return req.ResolveFlags == 0 && req.OpenHowSize == 0 && req.OpenHowVersion == 0 &&
			!req.OpenHowParsed && !req.OpenHowTrailingBytesZero
	}
	if !req.OpenHowParsed || !req.OpenHowTrailingBytesZero || req.OpenHowVersion != 0 || req.OpenHowSize < openHowSizeVersion0 || req.OpenHowSize > maxOpenHowSize {
		return false
	}
	// Without O_CREAT/O_TMPFILE, openat2 requires a zero mode.
	if req.OpenMode != 0 {
		return false
	}
	if req.ResolveFlags&^knownResolveFlagMask() != 0 || req.ResolveFlags&uint64(unix.RESOLVE_IN_ROOT) != 0 {
		return false
	}
	return true
}

func knownOpenFlagMask() uint64 {
	// These are all currently understood Linux open flags. Mutating and
	// semantically unsupported combinations are rejected separately above.
	return uint64(unix.O_ACCMODE |
		unix.O_APPEND |
		unix.O_ASYNC |
		unix.O_CLOEXEC |
		unix.O_CREAT |
		unix.O_DIRECT |
		unix.O_DIRECTORY |
		unix.O_DSYNC |
		unix.O_EXCL |
		unix.O_LARGEFILE |
		unix.O_NOATIME |
		unix.O_NOCTTY |
		unix.O_NOFOLLOW |
		unix.O_NONBLOCK |
		unix.O_PATH |
		unix.O_SYNC |
		unix.O_TMPFILE |
		unix.O_TRUNC)
}

func knownResolveFlagMask() uint64 {
	return uint64(unix.RESOLVE_NO_XDEV|
		unix.RESOLVE_NO_MAGICLINKS|
		unix.RESOLVE_NO_SYMLINKS|
		unix.RESOLVE_BENEATH|
		unix.RESOLVE_IN_ROOT) | resolveCached
}

func eligibleStatxLookup(req FileLookupRequest) bool {
	if !noOpenContext(req) || req.AccessMode != 0 || req.AccessFlags != 0 || req.ReadlinkBufferLen != 0 {
		return false
	}
	if !validStatxLookupFlags(req.LookupFlags) {
		return false
	}
	return req.StatMask&^knownStatxMask() == 0
}

func validStatxLookupFlags(flags uint32) bool {
	const syncType = uint32(unix.AT_STATX_FORCE_SYNC | unix.AT_STATX_DONT_SYNC)
	known := uint32(unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) | syncType
	if flags&uint32(unix.AT_EMPTY_PATH) != 0 || flags&^known != 0 {
		return false
	}
	// FORCE_SYNC and DONT_SYNC are mutually exclusive values, not bits that
	// may be combined.
	return flags&syncType != syncType
}

func knownStatxMask() uint32 {
	return uint32(unix.STATX_TYPE |
		unix.STATX_MODE |
		unix.STATX_NLINK |
		unix.STATX_UID |
		unix.STATX_GID |
		unix.STATX_ATIME |
		unix.STATX_MTIME |
		unix.STATX_CTIME |
		unix.STATX_INO |
		unix.STATX_SIZE |
		unix.STATX_BLOCKS |
		unix.STATX_BTIME |
		unix.STATX_MNT_ID |
		unix.STATX_DIOALIGN |
		unix.STATX_MNT_ID_UNIQUE |
		unix.STATX_SUBVOL |
		unix.STATX_WRITE_ATOMIC |
		unix.STATX_DIO_READ_ALIGN)
}

func eligibleNewfstatatLookup(req FileLookupRequest) bool {
	if !noOpenContext(req) || req.StatMask != 0 || req.AccessMode != 0 || req.AccessFlags != 0 || req.ReadlinkBufferLen != 0 {
		return false
	}
	known := uint32(unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT)
	return req.LookupFlags&uint32(unix.AT_EMPTY_PATH) == 0 && req.LookupFlags&^known == 0
}

func eligibleFaccessatLookup(req FileLookupRequest) bool {
	return eligibleAccessLookupContext(req) && req.AccessFlags == 0 && validAccessMode(req.AccessMode)
}

func eligibleFaccessat2Lookup(req FileLookupRequest) bool {
	if !eligibleAccessLookupContext(req) {
		return false
	}
	known := uint32(unix.AT_EACCESS | unix.AT_SYMLINK_NOFOLLOW)
	return validAccessMode(req.AccessMode) &&
		req.AccessFlags&uint32(unix.AT_EMPTY_PATH) == 0 &&
		req.AccessFlags&^known == 0
}

func eligibleAccessLookupContext(req FileLookupRequest) bool {
	return noOpenContext(req) && req.LookupFlags == 0 && req.StatMask == 0 && req.ReadlinkBufferLen == 0
}

func validAccessMode(mode uint32) bool {
	return mode&^uint32(unix.R_OK|unix.W_OK|unix.X_OK) == 0
}

func eligibleReadlinkLookup(req FileLookupRequest) bool {
	const maxReadlinkBufferLen = uint64(1<<31 - 1)
	return noOpenContext(req) && req.LookupFlags == 0 && req.StatMask == 0 &&
		req.AccessMode == 0 && req.AccessFlags == 0 && req.RawPath != "" &&
		req.ReadlinkBufferLen > 0 && req.ReadlinkBufferLen <= maxReadlinkBufferLen
}

func noOpenContext(req FileLookupRequest) bool {
	return req.OpenFlags == 0 && req.OpenMode == 0 && req.ResolveFlags == 0 &&
		req.OpenHowSize == 0 && req.OpenHowVersion == 0 && !req.OpenHowParsed &&
		!req.OpenHowTrailingBytesZero
}

// isProcDevMagicLinkPath rejects caller-relative procfs magic-link spellings
// and their conventional /dev aliases. Fixed proc files such as /proc/version
// are not classified as magic links here.
func isProcDevMagicLinkPath(path string) bool {
	if path == "" {
		return false
	}
	// Inspect the uncollapsed spelling first: filepath.Clean must not erase a
	// magic component that the kernel traverses before processing a later "..".
	if hasProcDevMagicLinkComponents(pathComponents(path)) {
		return true
	}
	clean := filepath.Clean(path)
	return clean != path && hasProcDevMagicLinkComponents(pathComponents(clean))
}

func pathComponents(path string) []string {
	raw := strings.Split(strings.TrimLeft(path, string(filepath.Separator)), string(filepath.Separator))
	parts := raw[:0]
	for _, component := range raw {
		if component != "" && component != "." {
			parts = append(parts, component)
		}
	}
	return parts
}

func hasProcDevMagicLinkComponents(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	if parts[0] == "dev" {
		if parts[1] == "fd" {
			return true
		}
		return parts[1] == "stdin" || parts[1] == "stdout" || parts[1] == "stderr"
	}
	if parts[0] != "proc" {
		return false
	}
	if parts[1] == "self" || parts[1] == "thread-self" {
		return true
	}
	if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
		return false
	}
	if len(parts) < 3 {
		return false
	}
	if isProcTaskMagicComponent(parts[2]) {
		return true
	}
	return len(parts) >= 5 && parts[2] == "task" && isDecimalComponent(parts[3]) && isProcTaskMagicComponent(parts[4])
}

func isProcTaskMagicComponent(component string) bool {
	switch component {
	case "cwd", "exe", "fd", "fdinfo", "map_files", "ns", "root":
		return true
	default:
		return false
	}
}

func isDecimalComponent(component string) bool {
	_, err := strconv.ParseUint(component, 10, 64)
	return err == nil
}
