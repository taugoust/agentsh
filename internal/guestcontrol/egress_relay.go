package guestcontrol

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const HostVSockCID uint32 = 2

// EgressRelay exposes one guest-loopback explicit HTTP proxy endpoint and
// opens a fresh stream to the host broker for every accepted connection. It
// does not interpret HTTP; the host-side netmonitor proxy remains the sole
// policy and dialing authority.
type EgressRelay struct {
	listener net.Listener
	dial     dialControlFunc
	hostPort uint32
	token    string
	proxyURL string

	closeOnce sync.Once
	closeErr  error
	connMu    sync.Mutex
	closing   bool
	conns     map[io.Closer]struct{}
}

// ListenEgressRelay binds an IPv4 loopback-only ephemeral TCP endpoint. Each
// accepted stream is relayed to host CID 2 at hostPort over AF_VSOCK.
func ListenEgressRelay(hostPort uint32, token string) (*EgressRelay, error) {
	if hostPort < 1024 || hostPort > 65535 || !validHexSecret(token) {
		return nil, fmt.Errorf("guest egress VSOCK endpoint or token is invalid")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return nil, fmt.Errorf("listen on guest egress loopback proxy: %w", err)
	}
	relay, err := newEgressRelay(listener, dialHostVSock, hostPort, token)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return relay, nil
}

func newEgressRelay(listener net.Listener, dial dialControlFunc, hostPort uint32, token string) (*EgressRelay, error) {
	if listener == nil || dial == nil || hostPort < 1024 || hostPort > 65535 || !validHexSecret(token) {
		return nil, fmt.Errorf("guest egress relay is not initialized")
	}
	address := listener.Addr()
	if address == nil {
		return nil, fmt.Errorf("guest egress loopback listener has no address")
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil, fmt.Errorf("inspect guest egress loopback listener: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("guest egress proxy listener is not loopback-only")
	}
	proxyURL := (&url.URL{Scheme: "http", Host: address.String()}).String()
	return &EgressRelay{
		listener: listener,
		dial:     dial,
		hostPort: hostPort,
		token:    token,
		proxyURL: proxyURL,
		conns:    make(map[io.Closer]struct{}),
	}, nil
}

func (r *EgressRelay) ProxyURL() string {
	if r == nil {
		return ""
	}
	return r.proxyURL
}

// ProbeHost proves that the immutable host CID/port reaches the strict HTTP
// proxy before the guest publishes explicit-proxy readiness. The deliberately invalid
// CONNECT authority is rejected before policy evaluation and cannot dial.
func (r *EgressRelay) ProbeHost(ctx context.Context) error {
	if r == nil || r.dial == nil {
		return fmt.Errorf("guest egress relay is not initialized")
	}
	connection, err := r.dial(ctx, HostVSockCID, r.hostPort)
	if err != nil {
		return fmt.Errorf("probe host egress VSOCK broker: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set host egress VSOCK probe deadline: %w", err)
	}
	if err := WriteEgressAuthentication(connection, r.token); err != nil {
		return err
	}
	const request = "CONNECT invalid HTTP/1.1\r\nHost: invalid\r\n\r\n"
	written, err := io.WriteString(connection, request)
	if err == nil && written != len(request) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write host egress VSOCK probe: %w", err)
	}
	status, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read host egress VSOCK probe: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 400 ") {
		return fmt.Errorf("host egress VSOCK probe received unexpected status %q", strings.TrimSpace(status))
	}
	return nil
}

func (r *EgressRelay) track(connections ...io.Closer) bool {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.closing {
		for _, connection := range connections {
			_ = connection.Close()
		}
		return false
	}
	for _, connection := range connections {
		r.conns[connection] = struct{}{}
	}
	return true
}

func (r *EgressRelay) untrack(connections ...io.Closer) {
	r.connMu.Lock()
	for _, connection := range connections {
		delete(r.conns, connection)
	}
	r.connMu.Unlock()
}

func (r *EgressRelay) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.connMu.Lock()
		r.closing = true
		connections := make([]io.Closer, 0, len(r.conns))
		for connection := range r.conns {
			connections = append(connections, connection)
		}
		r.connMu.Unlock()

		var listenerErr error
		if r.listener != nil {
			listenerErr = r.listener.Close()
		}
		for _, connection := range connections {
			_ = connection.Close()
		}
		r.closeErr = listenerErr
	})
	return r.closeErr
}

func (r *EgressRelay) Serve(ctx context.Context) error {
	if r == nil || r.listener == nil || r.dial == nil {
		return fmt.Errorf("guest egress relay is not initialized")
	}
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = r.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		guest, err := r.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("guest egress relay closed unexpectedly")
			}
			return fmt.Errorf("accept guest egress proxy stream: %w", err)
		}
		if !r.track(guest) {
			continue
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			host, dialErr := r.dial(ctx, HostVSockCID, r.hostPort)
			if dialErr != nil {
				r.untrack(guest)
				_ = guest.Close()
				return
			}
			authDeadline := time.Now().Add(5 * time.Second)
			if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(authDeadline) {
				authDeadline = contextDeadline
			}
			if deadlineErr := host.SetDeadline(authDeadline); deadlineErr != nil {
				dialErr = deadlineErr
			} else if authErr := WriteEgressAuthentication(host, r.token); authErr != nil {
				dialErr = authErr
			} else {
				dialErr = host.SetDeadline(time.Time{})
			}
			if dialErr != nil {
				r.untrack(guest)
				_ = guest.Close()
				_ = host.Close()
				return
			}
			if !r.track(host) {
				r.untrack(guest)
				return
			}
			defer r.untrack(guest, host)
			egressBridgeRelayStreams(ctx, guest, host)
		}()
	}
}

func egressBridgeRelayStreams(ctx context.Context, left, right io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	select {
	case <-ctx.Done():
	case <-done:
	}
	_ = left.Close()
	_ = right.Close()
	<-done
}
