package externalrunner

import (
	"fmt"
	"net"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

type vsockPeerAddress interface {
	net.Addr
	VSockCID() uint32
}

// verifiedVSockPeerListener rejects every stream whose kernel-reported peer
// CID differs from the immutable VM lease. Rejection happens before netmonitor
// can parse or act on any peer-controlled bytes.
type verifiedVSockPeerListener struct {
	listener       net.Listener
	expectedCID    uint32
	expectedToken  string
	authentication time.Duration
}

func verifyVSockPeerListener(listener net.Listener, expectedCID uint32, expectedToken string, authenticationTimeout time.Duration) (net.Listener, error) {
	if listener == nil || expectedCID < 3 || expectedCID == ^uint32(0) || authenticationTimeout <= 0 {
		return nil, fmt.Errorf("host egress VSOCK peer or authentication binding is invalid")
	}
	if !guestcontrol.ValidEgressAuthenticationToken(expectedToken) {
		return nil, fmt.Errorf("host egress VSOCK peer or authentication binding is invalid")
	}
	return &verifiedVSockPeerListener{listener: listener, expectedCID: expectedCID, expectedToken: expectedToken, authentication: authenticationTimeout}, nil
}

func (l *verifiedVSockPeerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, ok := connection.RemoteAddr().(vsockPeerAddress)
		if !ok || peer.VSockCID() != l.expectedCID {
			_ = connection.Close()
			continue
		}
		if err := connection.SetDeadline(time.Now().Add(l.authentication)); err != nil {
			_ = connection.Close()
			continue
		}
		if err := guestcontrol.ReadEgressAuthentication(connection, l.expectedToken); err != nil {
			_ = connection.Close()
			continue
		}
		if err := connection.SetDeadline(time.Time{}); err != nil {
			_ = connection.Close()
			continue
		}
		return connection, nil
	}
}

func (l *verifiedVSockPeerListener) Close() error   { return l.listener.Close() }
func (l *verifiedVSockPeerListener) Addr() net.Addr { return l.listener.Addr() }
