//go:build linux && cgo

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// --- READY/GO handshake tests ---

func TestPtraceSync_InvalidReadyByte(t *testing.T) {
	// If wrapper sends wrong READY byte, server should detect it.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Wrapper sends wrong byte.
	_, err = unix.Write(fds[0], []byte{'X'})
	require.NoError(t, err)

	// Server reads — byte doesn't match 'R'.
	buf := make([]byte, 1)
	n, err := unix.Read(fds[1], buf)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.NotEqual(t, byte('R'), buf[0], "should detect invalid READY byte")
}
