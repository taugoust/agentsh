//go:build linux && cgo && amd64

package unix

import "golang.org/x/sys/unix"

// isLegacyOpenSyscallNr returns true if nr is a legacy open-family syscall
// (SYS_OPEN, SYS_CREAT) that returns a file descriptor. Only present on x86_64.
func isLegacyOpenSyscallNr(nr int32) bool {
	return nr == unix.SYS_OPEN || nr == unix.SYS_CREAT
}

// legacyFileSyscallList returns the non-at legacy file syscalls present on x86_64.
// On x86_64, glibc wrappers for mkdir(), rmdir(), etc. issue these directly
// rather than the -at variants.
func legacyFileSyscallList() []int32 {
	return []int32{
		unix.SYS_OPEN,
		unix.SYS_CREAT,
		unix.SYS_MKDIR,
		unix.SYS_RMDIR,
		unix.SYS_UNLINK,
		unix.SYS_RENAME,
		unix.SYS_LINK,
		unix.SYS_SYMLINK,
		unix.SYS_CHMOD,
		unix.SYS_CHOWN,
	}
}

func legacyFlaggedOpenSyscallList() []int32 {
	return []int32{unix.SYS_OPEN}
}

func legacyMetadataSyscallList() []int32 {
	return []int32{unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_ACCESS, unix.SYS_READLINK}
}

// isLegacyFileSyscall returns true if nr is a legacy (non-at) file syscall.
func isLegacyFileSyscall(nr int32) bool {
	switch nr {
	case unix.SYS_OPEN, unix.SYS_CREAT,
		unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK,
		unix.SYS_RENAME, unix.SYS_LINK, unix.SYS_SYMLINK,
		unix.SYS_CHMOD, unix.SYS_CHOWN,
		unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_ACCESS, unix.SYS_READLINK:
		return true
	default:
		return false
	}
}

// extractLegacyFileArgs maps legacy (non-at) syscall arguments to FileArgs.
// Legacy syscalls have no dirfd argument; AT_FDCWD is used instead.
func extractLegacyFileArgs(args SyscallArgs) FileArgs {
	switch args.Nr {
	case unix.SYS_OPEN:
		// open(path, flags, mode)
		return FileArgs{
			Dirfd:     int32(unix.AT_FDCWD),
			PathPtr:   args.Arg0,
			Flags:     uint32(args.Arg1),
			Mode:      uint32(args.Arg2),
			OpenFlags: uint64(uint32(args.Arg1)),
			OpenMode:  uint64(uint32(args.Arg2)),
		}

	case unix.SYS_CREAT:
		// creat(path, mode) — equivalent to open(path, O_WRONLY|O_CREAT|O_TRUNC, mode).
		// Set implicit flags so isReadOnlyOpen and other flag checks work correctly.
		flags := uint32(unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC)
		return FileArgs{
			Dirfd:     int32(unix.AT_FDCWD),
			PathPtr:   args.Arg0,
			Flags:     flags,
			Mode:      uint32(args.Arg1),
			OpenFlags: uint64(flags),
			OpenMode:  uint64(uint32(args.Arg1)),
		}

	case unix.SYS_MKDIR:
		// mkdir(path, mode)
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg0,
			Mode:    uint32(args.Arg1),
		}

	case unix.SYS_RMDIR:
		// rmdir(path)
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg0,
		}

	case unix.SYS_UNLINK:
		// unlink(path)
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg0,
		}

	case unix.SYS_RENAME:
		// rename(oldpath, newpath)
		return FileArgs{
			Dirfd:         int32(unix.AT_FDCWD),
			PathPtr:       args.Arg0,
			HasSecondPath: true,
			Dirfd2:        int32(unix.AT_FDCWD),
			PathPtr2:      args.Arg1,
		}

	case unix.SYS_LINK:
		// link(oldpath, newpath)
		return FileArgs{
			Dirfd:         int32(unix.AT_FDCWD),
			PathPtr:       args.Arg0,
			HasSecondPath: true,
			Dirfd2:        int32(unix.AT_FDCWD),
			PathPtr2:      args.Arg1,
		}

	case unix.SYS_SYMLINK:
		// symlink(target, linkpath)
		// Primary path is the linkpath (where the symlink is created).
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg1, // linkpath
		}

	case unix.SYS_CHMOD:
		// chmod(path, mode)
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg0,
			Mode:    uint32(args.Arg1),
		}

	case unix.SYS_CHOWN:
		// chown(path, owner, group)
		return FileArgs{
			Dirfd:   int32(unix.AT_FDCWD),
			PathPtr: args.Arg0,
		}

	case unix.SYS_STAT:
		return FileArgs{Dirfd: int32(unix.AT_FDCWD), PathPtr: args.Arg0}
	case unix.SYS_LSTAT:
		return FileArgs{
			Dirfd: int32(unix.AT_FDCWD), PathPtr: args.Arg0,
			LookupFlags: uint32(unix.AT_SYMLINK_NOFOLLOW),
		}
	case unix.SYS_ACCESS:
		return FileArgs{
			Dirfd: int32(unix.AT_FDCWD), PathPtr: args.Arg0,
			AccessMode: uint32(args.Arg1),
		}
	case unix.SYS_READLINK:
		return FileArgs{
			Dirfd: int32(unix.AT_FDCWD), PathPtr: args.Arg0,
			ReadlinkBufferPtr: args.Arg1, ReadlinkBufferLen: args.Arg2,
		}

	default:
		return FileArgs{}
	}
}

// legacySyscallToOperation maps a legacy file syscall to a policy operation string.
func legacySyscallToOperation(nr int32, flags uint32) string {
	switch nr {
	case unix.SYS_OPEN:
		// Use the same O_CREAT|O_EXCL / O_TMPFILE semantics as openatOperation.
		if flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return "create"
		}
		if flags&(unix.O_CREAT|unix.O_EXCL) == (unix.O_CREAT | unix.O_EXCL) {
			return "create"
		}
		if flags&(unix.O_WRONLY|unix.O_RDWR|unix.O_APPEND|unix.O_TRUNC|unix.O_CREAT) != 0 {
			return "write"
		}
		return "open"
	case unix.SYS_CREAT:
		return "create"
	case unix.SYS_MKDIR:
		return "mkdir"
	case unix.SYS_RMDIR:
		return "rmdir"
	case unix.SYS_UNLINK:
		return "delete"
	case unix.SYS_RENAME:
		return "rename"
	case unix.SYS_LINK:
		return "link"
	case unix.SYS_SYMLINK:
		return "symlink"
	case unix.SYS_CHMOD:
		return "chmod"
	case unix.SYS_CHOWN:
		return "chown"
	case unix.SYS_STAT, unix.SYS_LSTAT:
		return "stat"
	case unix.SYS_ACCESS:
		return "access"
	case unix.SYS_READLINK:
		return "readlink"
	default:
		return ""
	}
}

func eligibleLegacyMissingLookup(req FileLookupRequest) bool {
	switch req.Syscall {
	case unix.SYS_OPEN:
		return eligibleOpenLookup(req, false)
	case unix.SYS_STAT:
		return eligibleLegacyStatLookup(req, 0)
	case unix.SYS_LSTAT:
		return eligibleLegacyStatLookup(req, uint32(unix.AT_SYMLINK_NOFOLLOW))
	case unix.SYS_ACCESS:
		return eligibleFaccessatLookup(req)
	case unix.SYS_READLINK:
		return eligibleReadlinkLookup(req)
	default:
		return false
	}
}

func eligibleLegacyStatLookup(req FileLookupRequest, expectedFlags uint32) bool {
	return noOpenContext(req) && req.LookupFlags == expectedFlags && req.StatMask == 0 &&
		req.AccessMode == 0 && req.AccessFlags == 0 && req.ReadlinkBufferLen == 0
}

// legacyFileSyscallName returns the human-readable name for a legacy file syscall.
func legacyFileSyscallName(nr int32) string {
	switch nr {
	case unix.SYS_OPEN:
		return "open"
	case unix.SYS_CREAT:
		return "creat"
	case unix.SYS_MKDIR:
		return "mkdir"
	case unix.SYS_RMDIR:
		return "rmdir"
	case unix.SYS_UNLINK:
		return "unlink"
	case unix.SYS_RENAME:
		return "rename"
	case unix.SYS_LINK:
		return "link"
	case unix.SYS_SYMLINK:
		return "symlink"
	case unix.SYS_CHMOD:
		return "chmod"
	case unix.SYS_CHOWN:
		return "chown"
	case unix.SYS_STAT:
		return "stat"
	case unix.SYS_LSTAT:
		return "lstat"
	case unix.SYS_ACCESS:
		return "access"
	case unix.SYS_READLINK:
		return "readlink"
	default:
		return ""
	}
}
