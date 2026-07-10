//go:build linux

package nethelper

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerInfo(conn net.Conn) PeerInfo {
	uc, ok := conn.(*net.UnixConn)
	if !ok || uc == nil {
		return PeerInfo{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerInfo{}
	}
	var out PeerInfo
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil || cred == nil {
			return
		}
		out = PeerInfo{PID: int(cred.Pid), UID: cred.Uid, GID: cred.Gid, Supported: true}
		identity, err := openProcessIdentity(out.PID)
		if err == nil {
			out.ProcessStartTime = identity.startTime
			out.identity = identity
		}
	})
	return out
}
