//go:build linux && cgo

package unix

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func openHowBuffer(size int, flags, mode, resolve uint64) []byte {
	buf := make([]byte, size)
	if size >= openHowSizeVersion0 {
		binary.NativeEndian.PutUint64(buf[0:8], flags)
		binary.NativeEndian.PutUint64(buf[8:16], mode)
		binary.NativeEndian.PutUint64(buf[16:24], resolve)
	}
	return buf
}

func readOwnOpenHow(t *testing.T, buf []byte, size uint64) (OpenHowContext, error) {
	t.Helper()
	ptr := uint64(1)
	if len(buf) > 0 {
		ptr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	}
	how, err := readOpenHowExact(os.Getpid(), ptr, size)
	runtime.KeepAlive(buf)
	return how, err
}

func TestReadOpenHowExact_PreservesAllVersion0Fields(t *testing.T) {
	flags := uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC)
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS)
	buf := openHowBuffer(openHowSizeVersion0, flags, 0, resolve)

	how, err := readOwnOpenHow(t, buf, uint64(len(buf)))
	require.NoError(t, err)
	assert.Equal(t, flags, how.Flags)
	assert.Zero(t, how.Mode)
	assert.Equal(t, resolve, how.Resolve)
	assert.Equal(t, uint64(openHowSizeVersion0), how.Size)
	assert.Zero(t, how.Version)
	assert.True(t, how.TrailingBytesZero)
}

func TestReadOpenHowExact_AcceptsOnlyZeroTrailingBytes(t *testing.T) {
	t.Run("larger compatible object", func(t *testing.T) {
		buf := openHowBuffer(openHowSizeVersion0+16, uint64(unix.O_RDONLY), 0, resolveCached)
		how, err := readOwnOpenHow(t, buf, uint64(len(buf)))
		require.NoError(t, err)
		assert.Equal(t, uint64(len(buf)), how.Size)
		assert.True(t, how.TrailingBytesZero)
	})

	t.Run("nonzero future field", func(t *testing.T) {
		buf := openHowBuffer(openHowSizeVersion0+8, uint64(unix.O_RDONLY), 0, 0)
		buf[openHowSizeVersion0] = 1
		_, err := readOwnOpenHow(t, buf, uint64(len(buf)))
		assert.ErrorIs(t, err, ErrOpenHowUnsupportedVersion)
	})
}

func TestReadOpenHowExact_RejectsShortPageBoundaryObject(t *testing.T) {
	pageSize := os.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, pageSize*2, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = unix.Mprotect(mapping[pageSize:], unix.PROT_READ|unix.PROT_WRITE)
		require.NoError(t, unix.Munmap(mapping))
	})

	start := pageSize - openHowSizeVersion0
	binary.NativeEndian.PutUint64(mapping[start:start+8], uint64(unix.O_RDONLY))
	binary.NativeEndian.PutUint64(mapping[start+8:start+16], 0)
	binary.NativeEndian.PutUint64(mapping[start+16:start+24], 0)
	require.NoError(t, unix.Mprotect(mapping[pageSize:], unix.PROT_NONE))

	_, err = readOpenHowExact(
		os.Getpid(),
		uint64(uintptr(unsafe.Pointer(&mapping[start]))),
		openHowSizeVersion0+8,
	)
	assert.ErrorIs(t, err, ErrReadMemory)
}

func TestReadOpenHowExact_RejectsInvalidSizes(t *testing.T) {
	t.Run("smaller than version zero", func(t *testing.T) {
		_, err := readOwnOpenHow(t, make([]byte, openHowSizeVersion0-1), openHowSizeVersion0-1)
		assert.ErrorIs(t, err, ErrOpenHowTooSmall)
	})
	t.Run("larger than bounded protocol object", func(t *testing.T) {
		_, err := readOwnOpenHow(t, []byte{0}, maxOpenHowSize+1)
		assert.ErrorIs(t, err, ErrOpenHowTooLarge)
	})
	t.Run("null pointer", func(t *testing.T) {
		_, err := readOpenHowExact(os.Getpid(), 0, openHowSizeVersion0)
		assert.ErrorIs(t, err, ErrNullPtr)
	})
}

func TestApplyOpenHowCarriesExactLookupContext(t *testing.T) {
	args := extractFileArgs(SyscallArgs{
		Nr: unix.SYS_OPENAT2, Arg0: fdcwdUint64(), Arg1: 0x1000,
		Arg2: 0x2000, Arg3: openHowSizeVersion0 + 8,
	})
	how := OpenHowContext{
		Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW), Resolve: resolveCached,
		Size: openHowSizeVersion0 + 8, Version: 0, TrailingBytesZero: true,
	}
	args.applyOpenHow(how)
	resolvedPath := filepath.Join(string(filepath.Separator), "work", "candidate")
	lookup := args.fileLookupRequest(123, unix.SYS_OPENAT2, "candidate", resolvedPath)

	assert.Equal(t, uint64(unix.O_PATH|unix.O_NOFOLLOW), lookup.OpenFlags)
	assert.Equal(t, resolveCached, lookup.ResolveFlags)
	assert.Equal(t, uint64(openHowSizeVersion0+8), lookup.OpenHowSize)
	assert.True(t, lookup.OpenHowParsed)
	assert.True(t, lookup.OpenHowTrailingBytesZero)
	assert.True(t, lookup.PathnameNULTerminated)
	assert.Equal(t, "candidate", lookup.RawPath)
	assert.Equal(t, resolvedPath, lookup.ResolvedPath)
}
