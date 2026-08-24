package guestcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ProxyRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Type            string `json:"type"`
	LaunchNonce     string `json:"launch_nonce"`
	SupervisorToken string `json:"supervisor_token"`
	RequestID       string `json:"request_id"`
}

type ProxyResponse struct {
	ProtocolVersion int    `json:"protocol_version"`
	Type            string `json:"type"`
	RequestID       string `json:"request_id"`
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
}

// SupervisorRelay exposes one protected guest AgentSH Unix socket over a
// separately authenticated VSOCK port. The raw supervisor is never published
// directly to the host.
type SupervisorRelay struct {
	server *Server
}

func ListenSupervisorRelay(port uint32) (*SupervisorRelay, error) {
	server, err := ListenVSock(port)
	if err != nil {
		return nil, err
	}
	return &SupervisorRelay{server: server}, nil
}

func (r *SupervisorRelay) Port() uint32 {
	if r == nil || r.server == nil {
		return 0
	}
	return r.server.Port()
}

func (r *SupervisorRelay) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}

func (r *SupervisorRelay) Serve(ctx context.Context, manifest Manifest, supervisorSocket string) error {
	if r == nil || r.server == nil || r.server.fd < 0 {
		return fmt.Errorf("guest supervisor relay is not initialized")
	}
	if !filepath.IsAbs(supervisorSocket) || filepath.Clean(supervisorSocket) != supervisorSocket {
		return fmt.Errorf("guest supervisor relay socket must be clean and absolute")
	}
	if r.Port() != manifest.SupervisorPort {
		return fmt.Errorf("guest supervisor relay port does not match the manifest")
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
		conn, err := acceptVSock(r.server.fd)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept guest supervisor relay connection: %w", err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			_ = relaySupervisorConnection(ctx, conn, manifest, supervisorSocket)
		}()
	}
}

func relaySupervisorConnection(ctx context.Context, host controlConn, manifest Manifest, supervisorSocket string) error {
	defer host.Close()
	_ = host.SetDeadline(time.Now().Add(defaultClientTimeout))
	reader := bufio.NewReader(io.LimitReader(host, MaxMessageBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > MaxMessageBytes {
		return writeProxyResponse(host, ProxyResponse{ProtocolVersion: ProtocolVersion, Type: "connect", OK: false, Error: "invalid proxy authentication"})
	}
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	var request ProxyRequest
	if err := decoder.Decode(&request); err != nil || requireJSONEOF(decoder) != nil ||
		request.ProtocolVersion != ProtocolVersion || request.Type != "connect" || !validName(request.RequestID) ||
		request.LaunchNonce != manifest.LaunchNonce || !secretEqual(request.SupervisorToken, manifest.SupervisorToken) {
		return writeProxyResponse(host, ProxyResponse{ProtocolVersion: ProtocolVersion, Type: "connect", RequestID: request.RequestID, OK: false, Error: "proxy authentication failed"})
	}

	guest, err := (&net.Dialer{}).DialContext(ctx, "unix", supervisorSocket)
	if err != nil {
		return writeProxyResponse(host, ProxyResponse{ProtocolVersion: ProtocolVersion, Type: "connect", RequestID: request.RequestID, OK: false, Error: "guest supervisor is unavailable"})
	}
	defer guest.Close()
	if err := writeProxyResponse(host, ProxyResponse{ProtocolVersion: ProtocolVersion, Type: "connect", RequestID: request.RequestID, OK: true}); err != nil {
		return err
	}
	if err := host.SetDeadline(time.Time{}); err != nil {
		return err
	}

	done := make(chan error, 2)
	go func() { _, copyErr := io.Copy(guest, reader); done <- copyErr }()
	go func() { _, copyErr := io.Copy(host, guest); done <- copyErr }()
	var firstErr error
	select {
	case <-ctx.Done():
		firstErr = ctx.Err()
	case firstErr = <-done:
	}
	_ = host.Close()
	_ = guest.Close()
	<-done
	return firstErr
}

func writeProxyResponse(writer io.Writer, response ProxyResponse) error {
	return json.NewEncoder(writer).Encode(response)
}

// ConnectSupervisor opens an authenticated byte stream to the exact guest
// AgentSH supervisor. The caller owns the returned connection.
func (c *Client) ConnectSupervisor(ctx context.Context) (io.ReadWriteCloser, error) {
	if c == nil || c.dial == nil {
		return nil, fmt.Errorf("guest control client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx, c.manifest.VSockCID, c.manifest.SupervisorPort)
	if err != nil {
		return nil, fmt.Errorf("dial guest supervisor endpoint: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	cancelWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-cancelWatch:
		}
	}()
	defer close(cancelWatch)
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, hasDeadline := ctx.Deadline(); hasDeadline && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	requestID := uuid.NewString()
	request := ProxyRequest{
		ProtocolVersion: ProtocolVersion,
		Type:            "connect",
		LaunchNonce:     c.manifest.LaunchNonce,
		SupervisorToken: c.manifest.SupervisorToken,
		RequestID:       requestID,
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, contextOrError(ctx, fmt.Errorf("write guest supervisor authentication: %w", err))
	}
	var response ProxyResponse
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(conn, MaxMessageBytes+1)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return nil, contextOrError(ctx, fmt.Errorf("read guest supervisor authentication: %w", err))
	}
	if response.ProtocolVersion != ProtocolVersion || response.Type != "connect" || response.RequestID != requestID {
		return nil, fmt.Errorf("guest supervisor authentication response identity mismatch")
	}
	if !response.OK || response.Error != "" {
		return nil, fmt.Errorf("guest supervisor authentication failed")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}
