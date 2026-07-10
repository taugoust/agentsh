//go:build !linux

package nethelper

import "net"

func peerInfo(net.Conn) PeerInfo { return PeerInfo{} }
