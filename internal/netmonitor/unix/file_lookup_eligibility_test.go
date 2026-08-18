//go:build linux && cgo

package unix

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func absoluteLookupPath(elements ...string) string {
	return filepath.Join(append([]string{string(filepath.Separator)}, elements...)...)
}

func baseMissingLookup(nr int32) FileLookupRequest {
	req := FileLookupRequest{
		TID:                   42,
		Syscall:               nr,
		DirFD:                 int32(unix.AT_FDCWD),
		RawPath:               "candidate",
		ResolvedPath:          absoluteLookupPath("work", "candidate"),
		PathnameNULTerminated: true,
	}
	switch nr {
	case unix.SYS_OPENAT:
		req.OpenFlags = uint64(unix.O_RDONLY)
	case unix.SYS_OPENAT2:
		req.OpenFlags = uint64(unix.O_RDONLY)
		req.OpenHowSize = openHowSizeVersion0
		req.OpenHowVersion = 0
		req.OpenHowParsed = true
		req.OpenHowTrailingBytesZero = true
	case unix.SYS_STATX:
		req.StatMask = uint32(unix.STATX_BASIC_STATS)
	case unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2:
		req.AccessMode = uint32(unix.F_OK)
	case unix.SYS_READLINKAT:
		req.ReadlinkBufferLen = 256
	}
	return req
}

func TestEligibleMissingLookup_AcceptsSupportedReadLookups(t *testing.T) {
	tests := []struct {
		name string
		req  FileLookupRequest
	}{
		{"openat read only", baseMissingLookup(unix.SYS_OPENAT)},
		{"openat directory", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_OPENAT)
			r.OpenFlags = uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC)
			return r
		}()},
		{"openat O_PATH no-follow", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_OPENAT)
			r.OpenFlags = uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC)
			return r
		}()},
		{"openat known non-mutating flags", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_OPENAT)
			r.OpenFlags = uint64(unix.O_RDONLY | unix.O_DIRECT | unix.O_NONBLOCK | unix.O_NOATIME | unix.O_NOCTTY)
			return r
		}()},
		{"openat2 version zero", baseMissingLookup(unix.SYS_OPENAT2)},
		{"openat2 zero extended object", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_OPENAT2)
			r.OpenHowSize = openHowSizeVersion0 + 8
			return r
		}()},
		{"openat2 supported resolve flags", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_OPENAT2)
			r.ResolveFlags = uint64(unix.RESOLVE_NO_XDEV|unix.RESOLVE_NO_MAGICLINKS|unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_BENEATH) | resolveCached
			return r
		}()},
		{"statx default", baseMissingLookup(unix.SYS_STATX)},
		{"statx no-follow force-sync", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_STATX)
			r.LookupFlags = uint32(unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT | unix.AT_STATX_FORCE_SYNC)
			r.StatMask = knownStatxMask()
			return r
		}()},
		{"newfstatat no-follow", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_NEWFSTATAT)
			r.LookupFlags = uint32(unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT)
			return r
		}()},
		{"faccessat permission modes", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_FACCESSAT)
			r.AccessMode = uint32(unix.R_OK | unix.W_OK | unix.X_OK)
			return r
		}()},
		{"faccessat2 effective no-follow", func() FileLookupRequest {
			r := baseMissingLookup(unix.SYS_FACCESSAT2)
			r.AccessMode = uint32(unix.X_OK)
			r.AccessFlags = uint32(unix.AT_EACCESS | unix.AT_SYMLINK_NOFOLLOW)
			return r
		}()},
		{"readlinkat nonempty", baseMissingLookup(unix.SYS_READLINKAT)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, eligibleMissingLookup(tt.req), "%+v", tt.req)
		})
	}
}

func TestEligibleMissingLookup_RejectsEveryOpenMutationAndAmbiguousForm(t *testing.T) {
	badFlags := []struct {
		name  string
		flags uint64
	}{
		{"O_WRONLY", uint64(unix.O_WRONLY)},
		{"O_RDWR", uint64(unix.O_RDWR)},
		{"invalid access mode", uint64(unix.O_ACCMODE)},
		{"O_CREAT", uint64(unix.O_CREAT)},
		{"O_TRUNC", uint64(unix.O_TRUNC)},
		{"O_APPEND", uint64(unix.O_APPEND)},
		{"O_TMPFILE", uint64(unix.O_TMPFILE)},
		{"O_EXCL without create", uint64(unix.O_EXCL)},
		{"non-O_PATH O_NOFOLLOW", uint64(unix.O_NOFOLLOW)},
		{"unknown high flag", uint64(1) << 63},
	}

	for _, nr := range []int32{unix.SYS_OPENAT, unix.SYS_OPENAT2} {
		for _, tt := range badFlags {
			t.Run(fileSyscallName(nr)+"/"+tt.name, func(t *testing.T) {
				req := baseMissingLookup(nr)
				req.OpenFlags = tt.flags
				assert.False(t, eligibleMissingLookup(req))
			})
		}
	}
}

func TestEligibleMissingLookup_RejectsInvalidOpenat2VersionsAndResolution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*FileLookupRequest)
	}{
		{"not fully parsed", func(r *FileLookupRequest) { r.OpenHowParsed = false }},
		{"trailing-byte validation not confirmed", func(r *FileLookupRequest) { r.OpenHowTrailingBytesZero = false }},
		{"short version", func(r *FileLookupRequest) { r.OpenHowSize = openHowSizeVersion0 - 1 }},
		{"oversized object", func(r *FileLookupRequest) { r.OpenHowSize = maxOpenHowSize + 1 }},
		{"unknown version", func(r *FileLookupRequest) { r.OpenHowVersion = 1 }},
		{"unconfirmed trailing bytes", func(r *FileLookupRequest) {
			r.OpenHowSize = openHowSizeVersion0 + 8
			r.OpenHowTrailingBytesZero = false
		}},
		{"mode without create", func(r *FileLookupRequest) { r.OpenMode = 0o600 }},
		{"RESOLVE_IN_ROOT", func(r *FileLookupRequest) { r.ResolveFlags = uint64(unix.RESOLVE_IN_ROOT) }},
		{"unknown resolve flag", func(r *FileLookupRequest) { r.ResolveFlags = uint64(1) << 63 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseMissingLookup(unix.SYS_OPENAT2)
			tt.mutate(&req)
			assert.False(t, eligibleMissingLookup(req))
		})
	}
}

func TestEligibleMissingLookup_RejectsInvalidMetadataForms(t *testing.T) {
	tests := []struct {
		name   string
		req    FileLookupRequest
		mutate func(*FileLookupRequest)
	}{
		{"statx AT_EMPTY_PATH", baseMissingLookup(unix.SYS_STATX), func(r *FileLookupRequest) { r.LookupFlags = uint32(unix.AT_EMPTY_PATH) }},
		{"statx unknown flag", baseMissingLookup(unix.SYS_STATX), func(r *FileLookupRequest) { r.LookupFlags = 1 << 30 }},
		{"statx conflicting sync", baseMissingLookup(unix.SYS_STATX), func(r *FileLookupRequest) {
			r.LookupFlags = uint32(unix.AT_STATX_FORCE_SYNC | unix.AT_STATX_DONT_SYNC)
		}},
		{"statx reserved mask", baseMissingLookup(unix.SYS_STATX), func(r *FileLookupRequest) { r.StatMask = uint32(unix.STATX__RESERVED) }},
		{"statx unknown mask", baseMissingLookup(unix.SYS_STATX), func(r *FileLookupRequest) { r.StatMask = 1 << 30 }},
		{"newfstatat AT_EMPTY_PATH", baseMissingLookup(unix.SYS_NEWFSTATAT), func(r *FileLookupRequest) { r.LookupFlags = uint32(unix.AT_EMPTY_PATH) }},
		{"newfstatat unknown flag", baseMissingLookup(unix.SYS_NEWFSTATAT), func(r *FileLookupRequest) { r.LookupFlags = 1 << 30 }},
		{"faccessat invalid mode", baseMissingLookup(unix.SYS_FACCESSAT), func(r *FileLookupRequest) { r.AccessMode = 8 }},
		{"faccessat has flags", baseMissingLookup(unix.SYS_FACCESSAT), func(r *FileLookupRequest) { r.AccessFlags = uint32(unix.AT_EACCESS) }},
		{"faccessat2 AT_EMPTY_PATH", baseMissingLookup(unix.SYS_FACCESSAT2), func(r *FileLookupRequest) { r.AccessFlags = uint32(unix.AT_EMPTY_PATH) }},
		{"faccessat2 unknown flag", baseMissingLookup(unix.SYS_FACCESSAT2), func(r *FileLookupRequest) { r.AccessFlags = 1 << 30 }},
		{"readlinkat empty", baseMissingLookup(unix.SYS_READLINKAT), func(r *FileLookupRequest) { r.RawPath = "" }},
		{"readlinkat zero buffer", baseMissingLookup(unix.SYS_READLINKAT), func(r *FileLookupRequest) { r.ReadlinkBufferLen = 0 }},
		{"readlinkat oversized buffer", baseMissingLookup(unix.SYS_READLINKAT), func(r *FileLookupRequest) { r.ReadlinkBufferLen = 1 << 31 }},
		{"readlinkat unrelated lookup flags", baseMissingLookup(unix.SYS_READLINKAT), func(r *FileLookupRequest) { r.LookupFlags = uint32(unix.AT_SYMLINK_NOFOLLOW) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mutate(&tt.req)
			assert.False(t, eligibleMissingLookup(tt.req))
		})
	}
}

func TestEligibleMissingLookup_RejectsUnconfirmedAndUnsupportedPathContexts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*FileLookupRequest)
	}{
		{"invalid TID", func(r *FileLookupRequest) { r.TID = 0 }},
		{"NUL not confirmed", func(r *FileLookupRequest) { r.PathnameNULTerminated = false }},
		{"embedded NUL", func(r *FileLookupRequest) { r.RawPath = "candidate\x00suffix" }},
		{"PATH_MAX bytes", func(r *FileLookupRequest) { r.RawPath = strings.Repeat("x", maxTraceePathnameLen) }},
		{"invalid relative dirfd", func(r *FileLookupRequest) { r.DirFD = -2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseMissingLookup(unix.SYS_OPENAT)
			tt.mutate(&req)
			assert.False(t, eligibleMissingLookup(req))
		})
	}

	// An absolute pathname ignores dirfd in the kernel, so an otherwise invalid
	// negative descriptor is still an exact supported form.
	req := baseMissingLookup(unix.SYS_OPENAT)
	req.RawPath = absoluteLookupPath("work", "candidate")
	req.DirFD = -2
	assert.True(t, eligibleMissingLookup(req))
}

func TestEligibleMissingLookup_RejectsProcAndDevMagicLinks(t *testing.T) {
	paths := []string{
		absoluteLookupPath("proc", "self", "status"),
		absoluteLookupPath("proc", "self") + string(filepath.Separator) + ".." + string(filepath.Separator) + "version",
		absoluteLookupPath("proc", "thread-self", "fd", "3"),
		absoluteLookupPath("proc", "123", "fd", "4"),
		absoluteLookupPath("proc", "123", "cwd", "file"),
		absoluteLookupPath("proc", "123", "task", "456", "ns", "mnt"),
		absoluteLookupPath("dev", "fd", "3"),
		absoluteLookupPath("dev", "fd") + string(filepath.Separator) + ".." + string(filepath.Separator) + "null",
		absoluteLookupPath("dev", "stdin"),
		absoluteLookupPath("dev", "stdout", "child"),
		absoluteLookupPath("dev", "stderr"),
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := baseMissingLookup(unix.SYS_OPENAT)
			req.RawPath = path
			req.ResolvedPath = path
			assert.False(t, eligibleMissingLookup(req))
		})
	}

	for _, path := range []string{
		absoluteLookupPath("proc", "version"),
		absoluteLookupPath("proc", "123", "status"),
		absoluteLookupPath("dev", "null"),
	} {
		t.Run("non-magic "+path, func(t *testing.T) {
			req := baseMissingLookup(unix.SYS_OPENAT)
			req.RawPath = path
			req.ResolvedPath = path
			assert.True(t, eligibleMissingLookup(req))
		})
	}

	t.Run("resolved spelling is independently guarded", func(t *testing.T) {
		req := baseMissingLookup(unix.SYS_OPENAT)
		req.RawPath = "status"
		req.ResolvedPath = absoluteLookupPath("proc", "self", "status")
		assert.False(t, eligibleMissingLookup(req))
	})
}

func TestEligibleMissingLookup_RejectsEveryMutationSyscall(t *testing.T) {
	mutations := []int32{
		unix.SYS_UNLINKAT,
		unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2,
		unix.SYS_LINKAT,
		unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT,
		unix.SYS_FCHOWNAT,
		unix.SYS_MKNODAT,
	}
	for _, nr := range mutations {
		t.Run(fileSyscallName(nr), func(t *testing.T) {
			assert.False(t, eligibleMissingLookup(baseMissingLookup(nr)))
		})
	}
	assert.False(t, eligibleMissingLookup(baseMissingLookup(unix.SYS_READ)), "unknown/unsupported syscall")
}
