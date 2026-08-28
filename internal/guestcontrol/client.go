package guestcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultClientTimeout = 30 * time.Second

type controlConn interface {
	deadlineReadWriter
	io.Closer
}

type dialControlFunc func(context.Context, uint32, uint32) (controlConn, error)

// Client is the authenticated host-side client for one exact guest control
// endpoint. It never accepts credentials or endpoint identity per operation.
type Client struct {
	manifest Manifest
	dial     dialControlFunc
	timeout  time.Duration
}

func NewVSockClient(manifest Manifest) (*Client, error) {
	return newClient(manifest, dialVSock, defaultClientTimeout)
}

func newClient(manifest Manifest, dial dialControlFunc, timeout time.Duration) (*Client, error) {
	if err := manifest.Validate(manifest.Workspace, manifest.Profile, manifest.ProfileDigest, []string{manifest.Policy}); err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, fmt.Errorf("guest control dialer is unavailable")
	}
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	return &Client{manifest: manifest, dial: dial, timeout: timeout}, nil
}

// Hello authenticates and validates the exact guest identity. Providers that
// publish ordinary Pi tools must require strict network readiness.
func (c *Client) Hello(ctx context.Context, requireNetworkReady bool) (Handshake, error) {
	response, err := c.exchange(ctx, "hello")
	if err != nil {
		return Handshake{}, err
	}
	if response.Handshake == nil {
		return Handshake{}, fmt.Errorf("guest control hello response omitted the handshake")
	}
	if err := response.Handshake.Validate(c.manifest); err != nil {
		return Handshake{}, err
	}
	if requireNetworkReady && !response.Handshake.NetworkReady {
		return Handshake{}, fmt.Errorf("guest control strict network enforcement is not ready")
	}
	return *response.Handshake, nil
}

func (c *Client) ExecProbe(ctx context.Context) (ExecProbeResult, error) {
	response, err := c.exchange(ctx, "exec_probe")
	if err != nil {
		return ExecProbeResult{}, err
	}
	if response.ExecProbe == nil {
		return ExecProbeResult{}, fmt.Errorf("guest control exec probe response omitted its result")
	}
	return *response.ExecProbe, nil
}

func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.exchange(ctx, "shutdown")
	return err
}

func (c *Client) exchange(ctx context.Context, operation string) (Response, error) {
	if c == nil || c.dial == nil {
		return Response{}, fmt.Errorf("guest control client is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	request := c.newRequest(operation)
	requestID := request.RequestID
	conn, err := c.dial(ctx, c.manifest.VSockCID, c.manifest.VSockPort)
	if err != nil {
		return Response{}, fmt.Errorf("dial guest control endpoint: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, fmt.Errorf("set guest control deadline: %w", err)
	}
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, contextOrError(ctx, fmt.Errorf("write guest control request: %w", err))
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxMessageBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return Response{}, contextOrError(ctx, fmt.Errorf("read guest control response: %w", err))
	}
	if len(line) > MaxMessageBytes {
		return Response{}, fmt.Errorf("guest control response exceeded limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(line)))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil || requireJSONEOF(decoder) != nil {
		return Response{}, fmt.Errorf("decode guest control response")
	}
	if response.ProtocolVersion != c.manifest.ProtocolVersion || response.Type != operation || response.RequestID != requestID {
		return Response{}, fmt.Errorf("guest control response identity mismatch")
	}
	if !response.OK {
		if strings.TrimSpace(response.Error) == "" {
			return Response{}, fmt.Errorf("guest control %s failed", operation)
		}
		return Response{}, fmt.Errorf("guest control %s failed: %s", operation, boundedError(errors.New(response.Error)))
	}
	if response.Error != "" {
		return Response{}, fmt.Errorf("guest control successful response included an error")
	}
	return response, nil
}

func (c *Client) newRequest(operation string) Request {
	return Request{
		ProtocolVersion: c.manifest.ProtocolVersion,
		Type:            operation,
		LaunchNonce:     c.manifest.LaunchNonce,
		ControlToken:    c.manifest.ControlToken,
		RequestID:       uuid.NewString(),
	}
}

func contextOrError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}
