package guestcontrol

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedSupervisorRelay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix supervisor sockets are unavailable on Windows")
	}
	manifest := testManifest(t.TempDir())
	socketPath := filepath.Join(t.TempDir(), "supervisor.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	guestDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
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
		go func() { _ = relaySupervisorConnection(context.Background(), server, manifest, socketPath) }()
		return client, nil
	}
	client, err := newClient(manifest, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.ConnectSupervisor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "pong" {
		t.Fatalf("response = %q", response)
	}
	if err := <-guestDone; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorRelayRejectsWrongCredential(t *testing.T) {
	manifest := testManifest(t.TempDir())
	clientManifest := manifest
	clientManifest.SupervisorToken = strings.Repeat("9", 64)
	dial := func(context.Context, uint32, uint32) (controlConn, error) {
		server, client := net.Pipe()
		go func() {
			_ = relaySupervisorConnection(context.Background(), server, manifest, filepath.Join(t.TempDir(), "unused.sock"))
		}()
		return client, nil
	}
	client, err := newClient(clientManifest, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := client.ConnectSupervisor(context.Background()); err == nil {
		_ = conn.Close()
		t.Fatal("guest supervisor relay accepted the wrong credential")
	}
}
