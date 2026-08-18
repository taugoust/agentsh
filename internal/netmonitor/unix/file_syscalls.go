//go:build linux && cgo

package unix

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// isOpenSyscall returns true if nr is an open-family syscall that returns a
// file descriptor. These are the syscalls eligible for AddFD emulation.
func isOpenSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return true
	default:
		return isLegacyOpenSyscallNr(nr)
	}
}

// isFileSyscall returns true if nr is a file I/O syscall we monitor.
func isFileSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2,
		unix.SYS_UNLINKAT, unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT, unix.SYS_FCHOWNAT,
		unix.SYS_STATX, unix.SYS_NEWFSTATAT, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
		unix.SYS_READLINKAT, unix.SYS_MKNODAT:
		return true
	default:
		return isLegacyFileSyscall(nr)
	}
}

// shouldFallbackToContinue returns true when an open-family syscall should
// use CONTINUE instead of AddFD emulation. This applies when:
//   - openat2 has non-zero RESOLVE_* flags (the supervisor cannot replicate
//     these resolution semantics).
//   - O_TMPFILE is used (file has no path to open via /proc/<pid>/root).
//
// emulableFlagMask is the set of open flags the supervisor can faithfully replicate.
const emulableFlagMask = unix.O_RDONLY | unix.O_WRONLY | unix.O_RDWR |
	unix.O_APPEND | unix.O_TRUNC | unix.O_CREAT | unix.O_EXCL |
	unix.O_NOFOLLOW | unix.O_DIRECTORY | unix.O_PATH | unix.O_NOCTTY |
	unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_SYNC | unix.O_DSYNC

// openatWriteMask defines flags that indicate a write/create operation.
// Built from unix constants for cross-architecture correctness.
// __O_TMPFILE is O_TMPFILE without O_DIRECTORY (O_TMPFILE = __O_TMPFILE|O_DIRECTORY).
const openatWriteMask = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT |
	unix.O_TRUNC | unix.O_APPEND | (unix.O_TMPFILE &^ unix.O_DIRECTORY)

// isReadOnlyOpen returns true if the flags indicate a read-only open
// (no write, create, truncate, append, or tmpfile flags set).
func isReadOnlyOpen(flags uint32) bool {
	return flags&openatWriteMask == 0
}

// isReadOnlyFileOp returns true if the syscall+flags combination represents
// a read-only file operation. For open-family syscalls this checks the open
// flags; for non-open syscalls it checks whether the syscall itself is
// inherently read-only (stat, access, readlink) vs mutating.
func isReadOnlyFileOp(nr int32, flags uint32) bool {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		return isReadOnlyOpen(flags)
	case unix.SYS_STATX, unix.SYS_NEWFSTATAT, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2, unix.SYS_READLINKAT:
		return true
	default:
		if isLegacyOpenSyscallNr(nr) {
			return isReadOnlyOpen(flags)
		}
		switch legacySyscallToOperation(nr, flags) {
		case "stat", "access", "readlink":
			return true
		}
		// All other file syscalls (unlinkat, mkdirat, renameat2, linkat,
		// symlinkat, fchmodat, fchownat, mknodat, and legacy equivalents)
		// are mutating operations.
		return false
	}
}

// shouldFallbackToContinue returns true when an open-family syscall should
// use CONTINUE instead of AddFD emulation. openat2 is ALWAYS routed to
// CONTINUE because its extended semantics (RESOLVE_* flags, how_size
// versioning, mode validation) cannot be faithfully replicated by the
// supervisor. Only plain openat/open/creat are emulated.
func shouldFallbackToContinue(nr int32, flags uint32, resolveFlags uint64) bool {
	// openat2: always CONTINUE — too many semantic edge cases to emulate safely.
	if nr == unix.SYS_OPENAT2 {
		return true
	}
	if flags&unix.O_TMPFILE == unix.O_TMPFILE {
		return true
	}
	// If the child passed flags the supervisor can't replicate, fall back
	// to CONTINUE rather than silently dropping bits.
	if flags & ^uint32(emulableFlagMask) != 0 {
		return true
	}
	return false
}

// shouldUseContinuePathForFileNotify reports whether a monitored file syscall
// should be policy-checked and then resumed in the tracee instead of completed
// by supervisor AddFD emulation. Mutating opens must stay in the tracee: the
// supervisor is privileged, so emulating O_CREAT/O_TRUNC/O_WRONLY as root would
// create or modify files with root credentials rather than the tracee's.
func shouldUseContinuePathForFileNotify(nr int32, flags uint32, resolveFlags uint64) bool {
	if !isOpenSyscall(nr) {
		return true
	}
	if shouldFallbackToContinue(nr, flags, resolveFlags) {
		return true
	}
	return !isReadOnlyOpen(flags)
}

// FileArgs holds parsed file syscall arguments. Flags and Mode remain the
// compatibility values used by policy/emulation. The syscall-family-specific
// fields retain exact lookup semantics without conflating unrelated arguments.
type FileArgs struct {
	Dirfd   int32
	PathPtr uint64
	Flags   uint32
	Mode    uint32

	OpenFlags   uint64
	OpenMode    uint64
	LookupFlags uint32
	StatMask    uint32
	AccessMode  uint32
	AccessFlags uint32

	ReadlinkBufferPtr uint64
	ReadlinkBufferLen uint64

	// For rename/link syscalls that operate on two paths.
	HasSecondPath bool
	Dirfd2        int32
	PathPtr2      uint64

	// For openat2: exact extensible-structure context. HowParsed is set only
	// after the complete supplied size and any trailing bytes are validated.
	HowPtr               uint64
	HowSize              uint64
	HowVersion           uint32
	HowParsed            bool
	HowTrailingBytesZero bool
	ResolveFlags         uint64
}

// extractFileArgs extracts file arguments based on syscall number.
func extractFileArgs(args SyscallArgs) FileArgs {
	switch args.Nr {
	case unix.SYS_OPENAT:
		// openat(dirfd, path, flags, mode)
		return FileArgs{
			Dirfd:     int32(args.Arg0),
			PathPtr:   args.Arg1,
			Flags:     uint32(args.Arg2),
			Mode:      uint32(args.Arg3),
			OpenFlags: uint64(uint32(args.Arg2)),
			OpenMode:  uint64(uint32(args.Arg3)),
		}

	case unix.SYS_OPENAT2:
		// openat2(dirfd, path, how, size)
		// Arg2 is a pointer to struct open_how in tracee memory.
		// Actual flags/mode must be read at runtime via ProcessVMReadv.
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			HowPtr:  args.Arg2,
			HowSize: args.Arg3,
		}

	case unix.SYS_UNLINKAT:
		// unlinkat(dirfd, path, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg2),
		}

	case unix.SYS_MKDIRAT:
		// mkdirat(dirfd, path, mode)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Mode:    uint32(args.Arg2),
		}

	case unix.SYS_RENAMEAT2:
		// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
		return FileArgs{
			Dirfd:         int32(args.Arg0),
			PathPtr:       args.Arg1,
			Flags:         uint32(args.Arg4),
			HasSecondPath: true,
			Dirfd2:        int32(args.Arg2),
			PathPtr2:      args.Arg3,
		}

	case unix.SYS_LINKAT:
		// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
		return FileArgs{
			Dirfd:         int32(args.Arg0),
			PathPtr:       args.Arg1,
			Flags:         uint32(args.Arg4),
			HasSecondPath: true,
			Dirfd2:        int32(args.Arg2),
			PathPtr2:      args.Arg3,
		}

	case unix.SYS_SYMLINKAT:
		// symlinkat(target, newdirfd, linkpath)
		// Primary path is the linkpath (where the symlink is created).
		return FileArgs{
			Dirfd:   int32(args.Arg1), // newdirfd
			PathPtr: args.Arg2,        // linkpath
		}

	case unix.SYS_FCHMODAT:
		// fchmodat(dirfd, path, mode, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Mode:    uint32(args.Arg2),
			Flags:   uint32(args.Arg3),
		}

	case unix.SYS_FCHOWNAT:
		// fchownat(dirfd, path, owner, group, flags)
		return FileArgs{
			Dirfd:   int32(args.Arg0),
			PathPtr: args.Arg1,
			Flags:   uint32(args.Arg4),
		}

	case unix.SYS_STATX:
		lookupFlags := uint32(args.Arg2)
		return FileArgs{
			Dirfd: int32(args.Arg0), PathPtr: args.Arg1,
			Flags: lookupFlags, LookupFlags: lookupFlags, StatMask: uint32(args.Arg3),
		}
	case unix.SYS_NEWFSTATAT:
		lookupFlags := uint32(args.Arg3)
		return FileArgs{
			Dirfd: int32(args.Arg0), PathPtr: args.Arg1,
			Flags: lookupFlags, LookupFlags: lookupFlags,
		}
	case unix.SYS_FACCESSAT:
		// faccessat(dirfd, path, mode) has no flags argument. Keeping mode in
		// Flags used to conflate X_OK/R_OK/W_OK with AT_* lookup flags.
		return FileArgs{
			Dirfd: int32(args.Arg0), PathPtr: args.Arg1,
			AccessMode: uint32(args.Arg2),
		}
	case unix.SYS_FACCESSAT2:
		accessFlags := uint32(args.Arg3)
		return FileArgs{
			Dirfd: int32(args.Arg0), PathPtr: args.Arg1,
			Flags: accessFlags, AccessMode: uint32(args.Arg2), AccessFlags: accessFlags,
		}
	case unix.SYS_READLINKAT:
		return FileArgs{
			Dirfd: int32(args.Arg0), PathPtr: args.Arg1,
			ReadlinkBufferPtr: args.Arg2, ReadlinkBufferLen: args.Arg3,
		}
	case unix.SYS_MKNODAT:
		return FileArgs{Dirfd: int32(args.Arg0), PathPtr: args.Arg1, Mode: uint32(args.Arg2)}

	default:
		return extractLegacyFileArgs(args)
	}
}

var (
	ErrOpenHowTooSmall           = errors.New("open_how is smaller than version 0")
	ErrOpenHowTooLarge           = errors.New("open_how exceeds the supported bound")
	ErrOpenHowUnsupportedVersion = errors.New("open_how has nonzero unknown trailing bytes")
)

// OpenHowContext is a completely read and version-checked open_how object.
// Size is the exact size supplied to openat2, not the size of this Go type.
type OpenHowContext struct {
	Flags             uint64
	Mode              uint64
	Resolve           uint64
	Size              uint64
	Version           uint32
	TrailingBytesZero bool
}

// readOpenHowExact reads the complete size supplied by the tracee. Linux's
// extensible-structure ABI accepts a larger object only when bytes beyond the
// latest understood version are zero; nonzero future fields are unsupported.
func readOpenHowExact(pid int, howPtr, howSize uint64) (OpenHowContext, error) {
	return readOpenHowExactImpl(pid, howPtr, howSize, false)
}

func readOpenHowExactWithFallback(pid int, howPtr, howSize uint64) (OpenHowContext, error) {
	return readOpenHowExactImpl(pid, howPtr, howSize, true)
}

func readOpenHowExactImpl(pid int, howPtr, howSize uint64, useFallback bool) (OpenHowContext, error) {
	if howPtr == 0 {
		return OpenHowContext{}, ErrNullPtr
	}
	if howSize < openHowSizeVersion0 {
		return OpenHowContext{}, fmt.Errorf("%w: got %d, need at least %d", ErrOpenHowTooSmall, howSize, openHowSizeVersion0)
	}
	if howSize > maxOpenHowSize {
		return OpenHowContext{}, fmt.Errorf("%w: got %d, maximum %d", ErrOpenHowTooLarge, howSize, maxOpenHowSize)
	}

	buf := make([]byte, int(howSize))
	liov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	riov := unix.RemoteIovec{Base: uintptr(howPtr), Len: len(buf)}
	n, readErr := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if readErr != nil || n != len(buf) {
		if !useFallback {
			if readErr != nil {
				return OpenHowContext{}, fmt.Errorf("%w: open_how: %v", ErrReadMemory, readErr)
			}
			return OpenHowContext{}, fmt.Errorf("%w: open_how: short read (%d/%d bytes)", ErrReadMemory, n, len(buf))
		}
		fallbackN, fallbackErr := readProcMemStrict(pid, howPtr, buf)
		if fallbackErr != nil || fallbackN != len(buf) {
			return OpenHowContext{}, fmt.Errorf(
				"%w: open_how: process_vm_readv: %v (%d/%d), /proc/mem: %v (%d/%d)",
				ErrReadMemory, readErr, n, len(buf), fallbackErr, fallbackN, len(buf),
			)
		}
	}

	for _, value := range buf[openHowSizeVersion0:] {
		if value != 0 {
			return OpenHowContext{}, ErrOpenHowUnsupportedVersion
		}
	}
	return OpenHowContext{
		Flags:             binary.NativeEndian.Uint64(buf[0:8]),
		Mode:              binary.NativeEndian.Uint64(buf[8:16]),
		Resolve:           binary.NativeEndian.Uint64(buf[16:24]),
		Size:              howSize,
		Version:           0,
		TrailingBytesZero: true,
	}, nil
}

func (a *FileArgs) applyOpenHow(how OpenHowContext) {
	a.OpenFlags = how.Flags
	a.OpenMode = how.Mode
	a.ResolveFlags = how.Resolve
	a.HowSize = how.Size
	a.HowVersion = how.Version
	a.HowParsed = true
	a.HowTrailingBytesZero = how.TrailingBytesZero

	// Compatibility fields are intentionally lossy and must never be used by
	// the missing-lookup classifier.
	a.Flags = uint32(how.Flags)
	a.Mode = uint32(how.Mode)
}

// readOpenHow is retained for existing policy/emulation callers. New lookup
// code must use readOpenHowExact so resolve and size semantics cannot be lost.
func readOpenHow(pid int, howPtr uint64) (flags uint64, mode uint64, err error) {
	how, err := readOpenHowExact(pid, howPtr, openHowSizeVersion0)
	if err != nil {
		return 0, 0, err
	}
	return how.Flags, how.Mode, nil
}

func readOpenHowWithFallback(pid int, howPtr uint64) (flags uint64, mode uint64, err error) {
	how, err := readOpenHowExactWithFallback(pid, howPtr, openHowSizeVersion0)
	if err != nil {
		return 0, 0, err
	}
	return how.Flags, how.Mode, nil
}

// readOpenHowResolve is retained for compatibility with callers that only need
// the version-0 resolve field. It still requires a complete eight-byte read.
func readOpenHowResolve(pid int, howPtr uint64) (uint64, error) {
	if howPtr == 0 {
		return 0, nil
	}
	var buf [8]byte
	liov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	riov := unix.RemoteIovec{Base: uintptr(howPtr + 16), Len: len(buf)}
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return 0, fmt.Errorf("read open_how resolve: %w", err)
	}
	if n != len(buf) {
		return 0, fmt.Errorf("%w: open_how resolve: short read (%d/%d bytes)", ErrReadMemory, n, len(buf))
	}
	return binary.NativeEndian.Uint64(buf[:]), nil
}

// syscallToOperation maps a file syscall number and flags to a policy operation string.
func syscallToOperation(nr int32, flags uint32) string {
	switch nr {
	case unix.SYS_OPENAT, unix.SYS_OPENAT2:
		// O_TMPFILE creates an unnamed temporary inode — always "create".
		if flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return "create"
		}
		// O_CREAT|O_EXCL is atomic exclusive creation (fails if file exists) — "create".
		// Plain O_CREAT without O_EXCL is open-or-create: behaves as "write" for
		// existing files, which is the shell-redirection pattern (> /dev/null).
		if flags&(unix.O_CREAT|unix.O_EXCL) == (unix.O_CREAT | unix.O_EXCL) {
			return "create"
		}
		if flags&(unix.O_WRONLY|unix.O_RDWR|unix.O_APPEND|unix.O_TRUNC|unix.O_CREAT) != 0 {
			return "write"
		}
		return "open"

	case unix.SYS_UNLINKAT:
		if flags&unix.AT_REMOVEDIR != 0 {
			return "rmdir"
		}
		return "delete"

	case unix.SYS_MKDIRAT:
		return "mkdir"
	case unix.SYS_RENAMEAT2:
		return "rename"
	case unix.SYS_LINKAT:
		return "link"
	case unix.SYS_SYMLINKAT:
		return "symlink"
	case unix.SYS_FCHMODAT:
		return "chmod"
	case unix.SYS_FCHOWNAT:
		return "chown"
	case unix.SYS_STATX, unix.SYS_NEWFSTATAT:
		return "stat"
	case unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2:
		return "access"
	case unix.SYS_READLINKAT:
		return "readlink"
	case unix.SYS_MKNODAT:
		return "mknod"
	default:
		return legacySyscallToOperation(nr, flags)
	}
}

// fileSyscallName returns the human-readable name for a file syscall number.
func fileSyscallName(nr int32) string {
	switch nr {
	case unix.SYS_OPENAT:
		return "openat"
	case unix.SYS_OPENAT2:
		return "openat2"
	case unix.SYS_UNLINKAT:
		return "unlinkat"
	case unix.SYS_MKDIRAT:
		return "mkdirat"
	case unix.SYS_RENAMEAT2:
		return "renameat2"
	case unix.SYS_LINKAT:
		return "linkat"
	case unix.SYS_SYMLINKAT:
		return "symlinkat"
	case unix.SYS_FCHMODAT:
		return "fchmodat"
	case unix.SYS_FCHOWNAT:
		return "fchownat"
	case unix.SYS_STATX:
		return "statx"
	case unix.SYS_NEWFSTATAT:
		return "newfstatat"
	case unix.SYS_FACCESSAT:
		return "faccessat"
	case unix.SYS_FACCESSAT2:
		return "faccessat2"
	case unix.SYS_READLINKAT:
		return "readlinkat"
	case unix.SYS_MKNODAT:
		return "mknodat"
	default:
		return legacyFileSyscallName(nr)
	}
}

// resolvePathAt reads a confirmed NUL-terminated pathname from tracee memory
// and resolves a policy path relative to the supplied dirfd.
func resolvePathAt(pid int, dirfd int32, pathPtr uint64) (string, error) {
	_, resolved, err := resolvePathAtDetailed(pid, dirfd, pathPtr, false)
	return resolved, err
}

// resolvePathAtWithFallback is like resolvePathAt but uses /proc/<pid>/mem
// when process_vm_readv itself fails. It never accepts a non-NUL partial read.
func resolvePathAtWithFallback(pid int, dirfd int32, pathPtr uint64) (string, error) {
	_, resolved, err := resolvePathAtDetailed(pid, dirfd, pathPtr, true)
	return resolved, err
}

func resolvePathAtWithRaw(pid int, dirfd int32, pathPtr uint64) (rawPath, resolvedPath string, err error) {
	return resolvePathAtDetailed(pid, dirfd, pathPtr, false)
}

func resolvePathAtWithRawFallback(pid int, dirfd int32, pathPtr uint64) (rawPath, resolvedPath string, err error) {
	return resolvePathAtDetailed(pid, dirfd, pathPtr, true)
}

func resolvePathAtDetailed(pid int, dirfd int32, pathPtr uint64, useFallback bool) (string, string, error) {
	var rawPath string
	var err error
	if useFallback {
		rawPath, err = readPathnameWithFallback(pid, pathPtr, maxTraceePathnameLen)
	} else {
		rawPath, err = readPathname(pid, pathPtr, maxTraceePathnameLen)
	}
	if err != nil {
		return "", "", fmt.Errorf("read path from tracee: %w", err)
	}

	if filepath.IsAbs(rawPath) {
		return rawPath, filepath.Clean(rawPath), nil
	}
	if dirfd == int32(unix.AT_FDCWD) {
		cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
		if err != nil {
			return rawPath, "", fmt.Errorf("resolve cwd for pid %d: %w", pid, err)
		}
		return rawPath, filepath.Clean(filepath.Join(cwd, rawPath)), nil
	}

	dirPath, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd))
	if err != nil {
		return rawPath, "", fmt.Errorf("resolve fd %d for pid %d: %w", dirfd, pid, err)
	}
	return rawPath, filepath.Clean(filepath.Join(dirPath, rawPath)), nil
}

// resolveProcFD detects and resolves /proc/self/fd/N, /proc/thread-self/fd/N,
// /proc/<pid>/fd/N, /dev/fd/N, and /dev/stdin|stdout|stderr paths to their
// actual targets. This prevents policy bypass by re-deriving paths from file
// descriptors.
//
// For /proc/<pid>/fd/N, accepts both the TID (task ID from seccomp notify)
// and the TGID (thread-group leader PID), since multi-threaded processes may
// reference either.
//
// Only substitutes the path when the resolved target is an absolute filesystem
// path. Pseudo-paths (pipe:[...], socket:[...], anon_inode:[...]) are left
// as-is since they are not subject to file policy.
func resolveProcFD(pid int, path string) (string, bool) {
	var fdStr string

	switch {
	case strings.HasPrefix(path, "/proc/self/fd/"):
		fdStr = path[len("/proc/self/fd/"):]
	case strings.HasPrefix(path, "/proc/thread-self/fd/"):
		fdStr = path[len("/proc/thread-self/fd/"):]
	case strings.HasPrefix(path, "/dev/fd/"):
		fdStr = path[len("/dev/fd/"):]
	case path == "/dev/stdin":
		fdStr = "0"
	case path == "/dev/stdout":
		fdStr = "1"
	case path == "/dev/stderr":
		fdStr = "2"
	default:
		if !matchesProcPidFD(pid, path, &fdStr) {
			return path, false
		}
	}

	// Split fd number from any trailing path components.
	// E.g., "/proc/self/fd/3/subpath" → fdNum="3", suffix="/subpath"
	var suffix string
	if slashIdx := strings.IndexByte(fdStr, '/'); slashIdx >= 0 {
		suffix = fdStr[slashIdx:]
		fdStr = fdStr[:slashIdx]
	}

	if _, err := strconv.Atoi(fdStr); err != nil {
		return path, false
	}

	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fdStr))
	if err != nil {
		return path, false
	}

	// Only substitute when the resolved target is an absolute filesystem path.
	// Pseudo-paths like pipe:[12345], socket:[...], anon_inode:[...] are not
	// subject to file policy evaluation.
	if !strings.HasPrefix(target, "/") {
		return path, false
	}
	// When a suffix exists (e.g., /proc/self/fd/3/subpath), verify that the
	// fd target is a directory. For non-directory fds, the kernel would return
	// ENOTDIR — don't rewrite the path (let the kernel handle it via CONTINUE).
	if suffix != "" {
		fi, err := os.Stat(target)
		if err != nil || !fi.IsDir() {
			return path, false
		}
		target = filepath.Clean(target + suffix)
	}
	return target, true
}

// matchesProcPidFD checks if path matches /proc/<N>/fd/<M> where N is either
// the given pid (TID) or the thread-group leader (TGID) of that pid.
func matchesProcPidFD(pid int, path string, fdStr *string) bool {
	// Try exact TID match first.
	prefix := fmt.Sprintf("/proc/%d/fd/", pid)
	if strings.HasPrefix(path, prefix) {
		*fdStr = path[len(prefix):]
		return true
	}

	// Try TGID match — in multi-threaded processes, the TID from seccomp
	// notify may differ from the process-level PID (TGID).
	tgid := readTGID(pid)
	if tgid > 0 && tgid != pid {
		prefix = fmt.Sprintf("/proc/%d/fd/", tgid)
		if strings.HasPrefix(path, prefix) {
			*fdStr = path[len(prefix):]
			return true
		}
	}

	return false
}

// readTGID reads the thread group ID (Tgid) from /proc/<tid>/status.
func readTGID(tid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Tgid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.Atoi(fields[1])
				if err == nil {
					return v
				}
			}
			break
		}
	}
	return 0
}
