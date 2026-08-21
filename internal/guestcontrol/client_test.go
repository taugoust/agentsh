package guestcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"
)

func pipeDialer(t *testing.T, manifest Manifest, handler Handler) dialControlFunc {
	t.Helper()
	return func(_ context.Context, cid, port uint32) (controlConn, error) {
		if cid != manifest.VSockCID || port != manifest.VSockPort {
			return nil, fmt.Errorf("unexpected endpoint %d:%d", cid, port)
		}
		server, client := net.Pipe()
		go func() {
			_, _ = handleConnection(context.Background(), server, manifest, handler)
			_ = server.Close()
		}()
		return client, nil
	}
}

func TestClientAuthenticatesGuestOperations(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handshake := testHandshake(manifest)
	handshake.NetworkReady = true
	handler := &fakeHandler{handshake: handshake}
	client, err := newClient(manifest, pipeDialer(t, manifest, handler), time.Second)
	if err != nil {
		t.Fatal(err)
	}

	gotHandshake, err := client.Hello(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotHandshake, handshake) {
		t.Fatalf("handshake = %+v, want %+v", gotHandshake, handshake)
	}
	probe, err := client.ExecProbe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if probe.ExitCode != 0 || probe.Stdout != "probe\n" {
		t.Fatalf("probe = %+v", probe)
	}
	if err := client.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if handler.execs != 1 || handler.shutdowns != 1 {
		t.Fatalf("handler calls exec=%d shutdown=%d", handler.execs, handler.shutdowns)
	}
}

func TestClientRefusesGuestWithoutStrictNetworkReadiness(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handler := &fakeHandler{handshake: testHandshake(manifest)}
	client, err := newClient(manifest, pipeDialer(t, manifest, handler), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Hello(context.Background(), true); err == nil {
		t.Fatal("strict host admission accepted a guest without network readiness")
	}
	if _, err := client.Hello(context.Background(), false); err != nil {
		t.Fatalf("diagnostic host admission rejected the expected bring-up guest: %v", err)
	}
}

func TestClientRejectsResponseIdentityMismatch(t *testing.T) {
	manifest := testManifest(t.TempDir())
	dial := func(context.Context, uint32, uint32) (controlConn, error) {
		server, client := net.Pipe()
		go func() {
			defer server.Close()
			var request Request
			_ = json.NewDecoder(server).Decode(&request)
			_ = json.NewEncoder(server).Encode(Response{
				ProtocolVersion: ProtocolVersion,
				Type:            request.Type,
				RequestID:       "substituted-request",
				OK:              true,
				Handshake:       func() *Handshake { value := testHandshake(manifest); return &value }(),
			})
		}()
		return client, nil
	}
	client, err := newClient(manifest, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Hello(context.Background(), false); err == nil {
		t.Fatal("guest response with a substituted request identity was accepted")
	}
}

func TestClientHonorsCancellationDuringDial(t *testing.T) {
	manifest := testManifest(t.TempDir())
	dial := func(ctx context.Context, _ uint32, _ uint32) (controlConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, err := newClient(manifest, dial, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Hello(ctx, false); err != context.Canceled {
		t.Fatalf("cancelled hello error = %v, want context.Canceled", err)
	}
}
