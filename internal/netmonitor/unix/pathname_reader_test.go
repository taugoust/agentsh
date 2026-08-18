//go:build linux && cgo

package unix

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadPathname_RequiresConfirmedNULTermination(t *testing.T) {
	t.Run("ordinary pathname", func(t *testing.T) {
		path := filepath.Join("relative", "path")
		buf := []byte(path + "\x00ignored")
		got, err := readPathname(os.Getpid(), uint64(uintptr(unsafe.Pointer(&buf[0]))), maxTraceePathnameLen)
		runtime.KeepAlive(buf)
		require.NoError(t, err)
		assert.Equal(t, path, got)
	})

	t.Run("empty pathname is still terminated", func(t *testing.T) {
		buf := []byte{0}
		got, err := readPathname(os.Getpid(), uint64(uintptr(unsafe.Pointer(&buf[0]))), 1)
		runtime.KeepAlive(buf)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	for _, tt := range []struct {
		name  string
		limit int
	}{
		{name: "zero read limit", limit: 0},
		{name: "read limit exceeds PATH_MAX", limit: maxTraceePathnameLen + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf := []byte{0}
			_, err := readPathname(os.Getpid(), uint64(uintptr(unsafe.Pointer(&buf[0]))), tt.limit)
			runtime.KeepAlive(buf)
			assert.ErrorIs(t, err, ErrInvalidPathnameReadLen)
		})
	}
}

func TestReadPathname_AcceptsNULAtPATHMAXBoundary(t *testing.T) {
	buf, err := unix.Mmap(-1, 0, maxTraceePathnameLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(buf)) })
	for i := 0; i < len(buf)-1; i++ {
		buf[i] = 'a'
	}
	buf[len(buf)-1] = 0

	got, err := readPathname(os.Getpid(), uint64(uintptr(unsafe.Pointer(&buf[0]))), maxTraceePathnameLen)
	require.NoError(t, err)
	assert.Len(t, got, maxTraceePathnameLen-1)
}

func TestReadPathname_RejectsPATHMAXBytesWithoutNUL(t *testing.T) {
	buf, err := unix.Mmap(-1, 0, maxTraceePathnameLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(buf)) })
	for i := range buf {
		buf[i] = 'x'
	}

	got, err := readPathname(os.Getpid(), uint64(uintptr(unsafe.Pointer(&buf[0]))), maxTraceePathnameLen)
	assert.Empty(t, got)
	assert.ErrorIs(t, err, ErrPathnameNotTerminated)
}

func TestReadPathname_RejectsShortPageBoundaryReadWithoutNUL(t *testing.T) {
	pageSize := os.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, pageSize*2, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = unix.Mprotect(mapping[pageSize:], unix.PROT_READ|unix.PROT_WRITE)
		require.NoError(t, unix.Munmap(mapping))
	})
	for i := pageSize - 8; i < pageSize; i++ {
		mapping[i] = 'q'
	}
	require.NoError(t, unix.Mprotect(mapping[pageSize:], unix.PROT_NONE))

	ptr := uint64(uintptr(unsafe.Pointer(&mapping[pageSize-8])))
	got, readErr := readPathname(os.Getpid(), ptr, maxTraceePathnameLen)
	assert.Empty(t, got)
	assert.Error(t, readErr)
	assert.True(t,
		errors.Is(readErr, ErrPathnameNotTerminated) || errors.Is(readErr, ErrReadMemory),
		"page-boundary failure must be a read or termination error, got %v", readErr,
	)
}

func TestResolvePathAtRejectsUnterminatedPathname(t *testing.T) {
	buf, err := unix.Mmap(-1, 0, maxTraceePathnameLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Munmap(buf)) })
	for i := range buf {
		buf[i] = 'z'
	}

	_, err = resolvePathAt(os.Getpid(), int32(unix.AT_FDCWD), uint64(uintptr(unsafe.Pointer(&buf[0]))))
	assert.ErrorIs(t, err, ErrPathnameNotTerminated)
}

func TestResolvePathAtWithRawPreservesExactPathname(t *testing.T) {
	separator := string(filepath.Separator)
	rawPath := "." + separator + "dir" + separator + ".." + separator + "candidate"
	buf := []byte(rawPath + "\x00")
	raw, resolved, err := resolvePathAtWithRaw(
		os.Getpid(),
		int32(unix.AT_FDCWD),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
	)
	runtime.KeepAlive(buf)
	require.NoError(t, err)
	assert.Equal(t, rawPath, raw)
	assert.NotEqual(t, raw, resolved)
}
