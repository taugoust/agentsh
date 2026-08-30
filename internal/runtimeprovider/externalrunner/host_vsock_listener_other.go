//go:build !linux

package externalrunner

import (
	"fmt"
	"net"
	"time"
)

func listenHostEgressVSock(uint32, uint32, string, time.Duration) (net.Listener, error) {
	return nil, fmt.Errorf("host egress VSOCK is supported only on Linux")
}
