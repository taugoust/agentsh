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
	"strings"
	"testing"
	"time"
)

func TestHostRelayPublishesAuthenticatedGuestSupervisor(t *testing.T) {
	manifest := testManifest(t.TempDir())
	guestSocket := filepath.Join(t.TempDir(), "guest-supervisor.sock")
	guestListener, err := net.Listen("unix", guestSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer guestListener.Close()
	guestDone := make(chan error, 1)
	go func() {
		conn, acceptErr := guestListener.Accept()
		if acceptErr != nil {
			guestDone <- acceptErr
			return
		}
		defer conn.Close()
		request := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			guestDone <- readErr
			return
		}
		if string(request) != "ping" {
			guestDone <- fmt.Errorf("request = %q", request)
			return
		}
		_, writeErr := conn.Write([]byte("pong"))
		guestDone <- writeErr
	}()

	dial := func(_ context.Context, cid, port uint32) (controlConn, error) {
		if cid != manifest.VSockCID || port != manifest.SupervisorPort {
			return nil, fmt.Errorf("unexpected endpoint %d:%d", cid, port)
		}
		server, client := net.Pipe()
		go func() { _ = relaySupervisorConnection(context.Background(), server, manifest, guestSocket) }()
		return client, nil
	}
	client, err := newClient(manifest, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	hostParent := t.TempDir()
	if err := os.Chmod(hostParent, 0o700); err != nil {
		t.Fatal(err)
	}
	hostPath := filepath.Join(hostParent, "host-supervisor.sock")
	relay, err := ListenHostRelay(hostPath, client)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("host relay mode = %v", info.Mode())
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- relay.Serve(ctx) }()

	host, err := net.Dial("unix", hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(host, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	_ = host.Close()
	if err := <-guestDone; err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-serveDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("host relay shutdown error = %v", err)
	}
	if _, err := os.Lstat(hostPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host relay socket survived shutdown: %v", err)
	}
}

func TestHostRelayRefusesToRemoveSubstitutedEndpoint(t *testing.T) {
	manifest := testManifest(t.TempDir())
	client, err := newClient(manifest, func(context.Context, uint32, uint32) (controlConn, error) {
		return nil, fmt.Errorf("unused")
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "supervisor.sock")
	relay, err := ListenHostRelay(path, client)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := relay.Close(); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("substituted endpoint cleanup error = %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement endpoint was removed or changed: %q, %v", data, err)
	}
}

func TestHostRelayRejectsUnsafeEndpoint(t *testing.T) {
	manifest := testManifest(t.TempDir())
	client, err := newClient(manifest, func(context.Context, uint32, uint32) (controlConn, error) {
		return nil, fmt.Errorf("unused")
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenHostRelay(filepath.Join(parent, "supervisor.sock"), client); err == nil {
		t.Fatal("host relay accepted a non-private parent directory")
	}
	privateParent := t.TempDir()
	if err := os.Chmod(privateParent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateParent, "supervisor.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenHostRelay(path, client); err == nil {
		t.Fatal("host relay replaced an existing endpoint")
	}
}
