//go:build !linux

package guestcontrol

import (
	"context"
	"fmt"
)

func ListenVSock(uint32) (*Server, error) {
	return nil, fmt.Errorf("guest control VSOCK is supported only on Linux")
}

func dialHostVSock(context.Context, uint32, uint32) (controlConn, error) {
	return nil, fmt.Errorf("guest egress VSOCK is supported only on Linux")
}

func dialVSock(context.Context, uint32, uint32) (controlConn, error) {
	return nil, fmt.Errorf("guest control VSOCK is supported only on Linux")
}

func acceptVSock(int) (controlConn, error) {
	return nil, fmt.Errorf("guest control VSOCK is supported only on Linux")
}

func closeVSock(int) error { return nil }
