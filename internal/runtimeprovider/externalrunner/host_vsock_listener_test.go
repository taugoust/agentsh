package externalrunner

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/guestcontrol"
)

type testVSockAddr struct {
	cid  uint32
	port uint32
}

func (a testVSockAddr) Network() string  { return "vsock" }
func (a testVSockAddr) String() string   { return "test-vsock" }
func (a testVSockAddr) VSockCID() uint32 { return a.cid }

type testVSockConn struct {
	net.Conn
	remote net.Addr
}

func (c testVSockConn) RemoteAddr() net.Addr { return c.remote }

type sequenceListener struct {
	mu     sync.Mutex
	addr   net.Addr
	conns  []net.Conn
	closed bool
}

func (l *sequenceListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	connection := l.conns[0]
	l.conns = l.conns[1:]
	return connection, nil
}
func (l *sequenceListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return nil
}
func (l *sequenceListener) Addr() net.Addr { return l.addr }

func TestVerifiedVSockListenerBoundsInitialAuthentication(t *testing.T) {
	token := strings.Repeat("4", 64)
	stalled, stalledPeer := net.Pipe()
	defer stalledPeer.Close()
	right, rightPeer := net.Pipe()
	defer rightPeer.Close()
	raw := &sequenceListener{
		addr: testVSockAddr{cid: 2, port: 41002},
		conns: []net.Conn{
			testVSockConn{Conn: stalled, remote: testVSockAddr{cid: 41002, port: 22000}},
			testVSockConn{Conn: right, remote: testVSockAddr{cid: 41002, port: 22001}},
		},
	}
	go func() { _ = guestcontrol.WriteEgressAuthentication(rightPeer, token) }()
	verified, err := verifyVSockPeerListener(raw, 41002, token, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	accepted, err := verified.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = accepted.Close()
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("authentication deadline elapsed %s", elapsed)
	}
	_ = stalledPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := stalledPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("stalled authentication stream remained open")
	}
}

func TestVerifiedVSockListenerRequiresExactPeerCIDAndLaunchTokenBeforeHTTP(t *testing.T) {
	token := strings.Repeat("4", 64)
	wrongCID, wrongCIDPeer := net.Pipe()
	defer wrongCIDPeer.Close()
	wrongToken, wrongTokenPeer := net.Pipe()
	defer wrongTokenPeer.Close()
	right, rightPeer := net.Pipe()
	defer rightPeer.Close()
	raw := &sequenceListener{
		addr: testVSockAddr{cid: 2, port: 41002},
		conns: []net.Conn{
			testVSockConn{Conn: wrongCID, remote: testVSockAddr{cid: 41001, port: 22000}},
			testVSockConn{Conn: wrongToken, remote: testVSockAddr{cid: 41002, port: 22001}},
			testVSockConn{Conn: right, remote: testVSockAddr{cid: 41002, port: 22002}},
		},
	}
	go func() {
		_ = guestcontrol.WriteEgressAuthentication(wrongTokenPeer, strings.Repeat("5", 64))
	}()
	go func() {
		_ = guestcontrol.WriteEgressAuthentication(rightPeer, token)
		_, _ = rightPeer.Write([]byte("CONNECT exact.example:443 HTTP/1.1\r\n"))
	}()
	verified, err := verifyVSockPeerListener(raw, 41002, token, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := verified.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if peer := accepted.RemoteAddr().(vsockPeerAddress); peer.VSockCID() != 41002 {
		t.Fatalf("accepted peer CID = %d", peer.VSockCID())
	}
	buffer := make([]byte, len("CONNECT exact.example:443 HTTP/1.1\r\n"))
	if _, err := io.ReadFull(accepted, buffer); err != nil || string(buffer) != "CONNECT exact.example:443 HTTP/1.1\r\n" {
		t.Fatalf("first accepted HTTP bytes = %q, %v", buffer, err)
	}
	buffer = buffer[:1]
	if _, err := wrongCIDPeer.Read(buffer); err == nil {
		t.Fatal("wrong-CID stream remained open")
	}
	if _, err := wrongTokenPeer.Read(buffer); err == nil {
		t.Fatal("wrong-token stream remained open")
	}
}
