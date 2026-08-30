package guestcontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEgressRelayUsesLoopbackAndHostCIDPerStream(t *testing.T) {
	token := strings.Repeat("4", 64)
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Skipf("IPv4 loopback is unavailable: %v", err)
	}
	type dialResult struct {
		cid  uint32
		port uint32
		peer net.Conn
	}
	dials := make(chan dialResult, 1)
	relay, err := newEgressRelay(listener, func(_ context.Context, cid, port uint32) (controlConn, error) {
		guest, host := net.Pipe()
		dials <- dialResult{cid: cid, port: port, peer: host}
		return guest, nil
	}, 19083, token)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	parsed, err := url.Parse(relay.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(parsed.Host)
	if err != nil || !net.ParseIP(host).IsLoopback() || parsed.Scheme != "http" {
		t.Fatalf("egress proxy URL = %q", relay.ProxyURL())
	}

	probeResult := make(chan error, 1)
	go func() { probeResult <- relay.ProbeHost(context.Background()) }()
	probe := <-dials
	if probe.cid != HostVSockCID || probe.port != 19083 {
		t.Fatalf("probe VSOCK dial = cid %d port %d", probe.cid, probe.port)
	}
	if err := ReadEgressAuthentication(probe.peer, token); err != nil {
		t.Fatalf("probe authentication: %v", err)
	}
	probeRequest := make([]byte, 512)
	n, err := probe.peer.Read(probeRequest)
	if err != nil || !strings.Contains(string(probeRequest[:n]), "CONNECT invalid") {
		t.Fatalf("host probe request = %q, %v", probeRequest[:n], err)
	}
	if _, err := probe.peer.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := <-probeResult; err != nil {
		t.Fatal(err)
	}
	_ = probe.peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- relay.Serve(ctx) }()
	local, err := net.DialTimeout("tcp4", parsed.Host, time.Second)
	if err != nil {
		cancel()
		_ = relay.Close()
		t.Fatal(err)
	}
	defer local.Close()

	var dial dialResult
	select {
	case dial = <-dials:
	case <-time.After(time.Second):
		t.Fatal("loopback stream did not open a host VSOCK stream")
	}
	defer dial.peer.Close()
	if dial.cid != HostVSockCID || dial.port != 19083 {
		t.Fatalf("VSOCK dial = cid %d port %d, want cid %d port 19083", dial.cid, dial.port, HostVSockCID)
	}
	if err := ReadEgressAuthentication(dial.peer, token); err != nil {
		t.Fatalf("stream authentication: %v", err)
	}
	if _, err := local.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(dial.peer, request); err != nil || string(request) != "request" {
		t.Fatalf("relayed request = %q, %v", request, err)
	}
	if _, err := dial.peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("response"))
	if _, err := io.ReadFull(local, response); err != nil || string(response) != "response" {
		t.Fatalf("relayed response = %q, %v", response, err)
	}

	cancel()
	_ = relay.Close()
	select {
	case err := <-served:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("egress relay did not stop with its context")
	}
}
