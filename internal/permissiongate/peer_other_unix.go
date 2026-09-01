//go:build !linux && !windows

package permissiongate

import (
	"errors"
	"net"
)

// Platforms without Linux SO_PEERCRED still retain the private mode-0700,
// random, one-shot rendezvous. Permission Gate is currently deployed on Linux;
// this keeps the command buildable on other supported Unix targets.
func verifyPermissionGatePeer(connection *net.UnixConn, expectedPID int) error {
	if connection == nil || expectedPID <= 0 {
		return errors.New("invalid permission gate peer claim")
	}
	return nil
}
