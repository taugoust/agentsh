package guestcontrol

import (
	"context"
	"encoding/json"
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

func TestSupervisorRelayServerRetainsProtocolV2Authentication(t *testing.T) {
	manifest := testManifest(t.TempDir())
	manifest.ProtocolVersion = ProtocolVersionV2
	manifest.VolumeID = ""
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- relaySupervisorConnection(context.Background(), server, manifest, filepath.Join(t.TempDir(), "missing.sock"))
	}()
	request := ProxyRequest{
		ProtocolVersion: manifest.ProtocolVersion, Type: "connect", RequestID: "legacy-connect",
		LaunchNonce: manifest.LaunchNonce, SupervisorToken: manifest.SupervisorToken,
	}
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response ProxyResponse
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != ProtocolVersionV2 || response.OK || response.RequestID != request.RequestID || response.Error != "guest supervisor is unavailable" {
		t.Fatalf("legacy proxy response = %+v", response)
	}
}

func TestSupervisorRelayClientRetainsProtocolV2Authentication(t *testing.T) {
	manifest := testManifest(t.TempDir())
	manifest.ProtocolVersion = ProtocolVersionV2
	manifest.VolumeID = ""
	requestSeen := make(chan ProxyRequest, 1)
	dial := func(context.Context, uint32, uint32) (controlConn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			var request ProxyRequest
			if err := json.NewDecoder(server).Decode(&request); err != nil {
				return
			}
			requestSeen <- request
			_ = json.NewEncoder(server).Encode(ProxyResponse{
				ProtocolVersion: request.ProtocolVersion, Type: "connect", RequestID: request.RequestID, OK: true,
			})
			_, _ = io.Copy(io.Discard, server)
		}()
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
	_ = conn.Close()
	request := <-requestSeen
	if request.ProtocolVersion != ProtocolVersionV2 {
		t.Fatalf("legacy proxy request protocol = %d", request.ProtocolVersion)
	}
}

func TestConnectSupervisorCancellationInterruptsAuthentication(t *testing.T) {
	manifest := testManifest(t.TempDir())
	dial := func(context.Context, uint32, uint32) (controlConn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			_, _ = io.Copy(io.Discard, server)
		}()
		return client, nil
	}
	client, err := newClient(manifest, dial, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		conn, connectErr := client.ConnectSupervisor(ctx)
		if conn != nil {
			_ = conn.Close()
		}
		result <- connectErr
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
			t.Fatalf("ConnectSupervisor cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ConnectSupervisor did not interrupt authentication on cancellation")
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
