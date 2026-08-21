//go:build !windows

package guestcontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// HostRelay owns the mode-0600 Unix endpoint consumed by existing AgentSH
// clients and opens one authenticated guest supervisor stream per connection.
type HostRelay struct {
	path     string
	identity os.FileInfo
	listener *net.UnixListener
	client   *Client

	closeOnce sync.Once
	closeErr  error
}

func ListenHostRelay(path string, client *Client) (*HostRelay, error) {
	if client == nil {
		return nil, fmt.Errorf("guest control client is unavailable")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("host guest-relay path must be clean and absolute")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("host guest-relay directory is not private")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return nil, fmt.Errorf("host guest-relay path already exists")
		}
		return nil, fmt.Errorf("inspect host guest-relay path: %w", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on host guest-relay socket: %w", err)
	}
	// Go otherwise unlinks whatever currently occupies path on Close, even if
	// an attacker replaced the socket after bind. Cleanup below is identity-bound.
	listener.SetUnlinkOnClose(false)
	boundInfo, err := os.Lstat(path)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("inspect bound host guest-relay socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = listener.Close()
			if current, statErr := os.Lstat(path); statErr == nil && os.SameFile(boundInfo, current) {
				_ = os.Remove(path)
			}
		}
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect host guest-relay socket: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("host guest-relay socket identity or permissions are invalid")
	}
	ok = true
	return &HostRelay{path: path, identity: info, listener: listener, client: client}, nil
}

func (r *HostRelay) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

func (r *HostRelay) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		var closeErr error
		if r.listener != nil {
			closeErr = r.listener.Close()
		}
		var removeErr error
		current, statErr := os.Lstat(r.path)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
		case statErr != nil:
			removeErr = statErr
		case r.identity == nil || !os.SameFile(r.identity, current):
			removeErr = fmt.Errorf("host guest-relay endpoint identity changed before cleanup")
		default:
			removeErr = os.Remove(r.path)
		}
		r.closeErr = errors.Join(closeErr, removeErr)
	})
	return r.closeErr
}

func (r *HostRelay) Serve(ctx context.Context) error {
	if r == nil || r.listener == nil || r.client == nil {
		return fmt.Errorf("host guest-relay is not initialized")
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
		host, err := r.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return errors.Join(ctx.Err(), r.Close())
			}
			return fmt.Errorf("accept host guest-relay connection: %w", err)
		}
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer host.Close()
			guest, connectErr := r.client.ConnectSupervisor(ctx)
			if connectErr != nil {
				return
			}
			defer guest.Close()
			bridgeRelayStreams(ctx, host, guest)
		}()
	}
}

func bridgeRelayStreams(ctx context.Context, left, right io.ReadWriteCloser) {
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
