//go:build !linux

package guestcontrol

import (
	"fmt"
	"os"
)

func ListenVSock(uint32) (*Server, error) {
	return nil, fmt.Errorf("guest control VSOCK is supported only on Linux")
}

func acceptVSock(int) (*os.File, error) {
	return nil, fmt.Errorf("guest control VSOCK is supported only on Linux")
}

func closeVSock(int) error { return nil }
