package netmonitor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type strictAuditTestEmitter struct {
	mu sync.Mutex

	calls       []string
	events      []types.Event
	appendError map[string]error
	flushError  error
}

func (e *strictAuditTestEmitter) record(call string) {
	e.mu.Lock()
	e.calls = append(e.calls, call)
	e.mu.Unlock()
}

func (e *strictAuditTestEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	e.mu.Lock()
	e.calls = append(e.calls, "append:"+ev.Type)
	e.events = append(e.events, ev)
	err := e.appendError[ev.Type]
	e.mu.Unlock()
	return err
}

func (e *strictAuditTestEmitter) Publish(ev types.Event) {
	e.record("publish:" + ev.Type)
}

func (e *strictAuditTestEmitter) FlushSync(context.Context) error {
	e.mu.Lock()
	e.calls = append(e.calls, "flush")
	err := e.flushError
	e.mu.Unlock()
	return err
}

func (e *strictAuditTestEmitter) snapshot() ([]string, []types.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...), append([]types.Event(nil), e.events...)
}

type nonDurableTestEmitter struct{}

func (nonDurableTestEmitter) AppendEvent(context.Context, types.Event) error { return nil }
func (nonDurableTestEmitter) Publish(types.Event)                            {}

func TestStartProxyWithOptionsUsesInjectedListener(t *testing.T) {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Skipf("listen tcp4 is unavailable: %v", err)
	}
	emitter := &strictAuditTestEmitter{}
	p, proxyURL, err := StartProxyWithOptions(ProxyStartOptions{
		Listener:           ln,
		StrictPublicEgress: true,
	}, "session-listener", nil, nil, nil, emitter)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("StartProxyWithOptions: %v", err)
	}
	defer p.Close()

	if p.ln != ln {
		t.Fatal("proxy did not retain the injected listener")
	}
	if !p.strictPublicEgress {
		t.Fatal("proxy did not apply strict public-egress mode")
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	if parsed.Host != ln.Addr().String() {
		t.Fatalf("proxy URL host = %q, want injected listener %q", parsed.Host, ln.Addr())
	}
}

func TestStartProxyStrictModeRequiresDurableEmitter(t *testing.T) {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Skipf("listen tcp4 is unavailable: %v", err)
	}
	defer ln.Close()

	_, _, err = StartProxyWithOptions(ProxyStartOptions{
		Listener:           ln,
		StrictPublicEgress: true,
	}, "session-strict", nil, nil, nil, nonDurableTestEmitter{})
	if err == nil || !strings.Contains(err.Error(), "durable") {
		t.Fatalf("strict startup error = %v, want durable-emitter rejection", err)
	}
}

func TestStrictProxyCapsConnectionsAndInitialRequestTime(t *testing.T) {
	p := &Proxy{maxConnections: 1, initialRequestTimeout: 20 * time.Millisecond, conns: make(map[net.Conn]struct{})}
	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	if !p.trackConn(first) {
		t.Fatal("first connection was refused")
	}
	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	if p.trackConn(second) {
		t.Fatal("connection cap admitted a second connection")
	}
	_ = secondPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := secondPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("capped connection was not closed")
	}
	p.untrackConn(first)
	_ = first.Close()

	client, server := net.Pipe()
	handled := make(chan error, 1)
	go func() { handled <- p.handleConn(server) }()
	select {
	case err := <-handled:
		if err == nil {
			t.Fatal("initial request timeout returned nil")
		}
	case <-time.After(time.Second):
		t.Fatal("initial HTTP request deadline did not bound the handler")
	}
	_ = client.Close()
}

func TestStrictProxyFatalAuditFailureSignalsDone(t *testing.T) {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Skipf("listen tcp4 is unavailable: %v", err)
	}
	emitter := &strictAuditTestEmitter{appendError: map[string]error{"net_connect": errors.New("audit failed")}}
	p, _, err := StartProxyWithOptions(ProxyStartOptions{Listener: ln, StrictPublicEgress: true}, "session-health", nil, nil, nil, emitter)
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
	if err != nil {
		_ = p.Close()
		t.Fatal(err)
	}
	_, _ = io.WriteString(client, "CONNECT 8.8.8.8:8443 HTTP/1.1\r\nHost: 8.8.8.8:8443\r\n\r\n")
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = client.Read(make([]byte, 256))
	_ = client.Close()
	select {
	case <-p.Done():
		if p.Err() == nil || !strings.Contains(p.Err().Error(), "audit") {
			t.Fatalf("fatal proxy error = %v", p.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("fatal strict proxy audit failure did not signal Done")
	}
}

func TestProxyPublicEgressPerimeter(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public IPv4", ip: "8.8.8.8", want: true},
		{name: "public IPv6", ip: "2606:4700:4700::1111", want: true},
		{name: "mapped public IPv4", ip: "::ffff:8.8.8.8", want: true},
		{name: "unspecified IPv4", ip: "0.0.0.0"},
		{name: "reserved this-network", ip: "0.1.2.3"},
		{name: "loopback IPv4", ip: "127.0.0.42"},
		{name: "private 10", ip: "10.0.0.1"},
		{name: "private 172", ip: "172.31.255.255"},
		{name: "private 192", ip: "192.168.1.1"},
		{name: "CGNAT", ip: "100.64.0.1"},
		{name: "CGNAT upper bound", ip: "100.127.255.255"},
		{name: "link-local IPv4", ip: "169.254.10.20"},
		{name: "multicast IPv4", ip: "239.1.2.3"},
		{name: "reserved IPv4", ip: "240.0.0.1"},
		{name: "documentation one", ip: "192.0.2.1"},
		{name: "documentation two", ip: "198.51.100.1"},
		{name: "documentation three", ip: "203.0.113.1"},
		{name: "benchmark IPv4", ip: "198.18.0.1"},
		{name: "unspecified IPv6", ip: "::"},
		{name: "loopback IPv6", ip: "::1"},
		{name: "mapped private IPv4", ip: "::ffff:10.0.0.1"},
		{name: "unique-local IPv6", ip: "fd00::1"},
		{name: "link-local IPv6", ip: "fe80::1"},
		{name: "multicast IPv6", ip: "ff02::1"},
		{name: "documentation IPv6", ip: "2001:db8::1"},
		{name: "new documentation IPv6", ip: "3fff::1"},
		{name: "deprecated 6bone IPv6", ip: "3ffe::1"},
		{name: "unallocated IPv6", ip: "4000::1"},
		{name: "benchmark IPv6", ip: "2001:2::1"},
		{name: "reserved IETF IPv6", ip: "2001:100::1"},
		{name: "discard-only IPv6", ip: "100::1"},
		{name: "deprecated site-local IPv6", ip: "fec0::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			if got := IsPublicEgressIP(addr); got != tt.want {
				t.Fatalf("IsPublicEgressIP(%s) = %v, want %v", addr, got, tt.want)
			}
			err := ValidatePublicEgressIP(addr)
			if tt.want && err != nil {
				t.Fatalf("ValidatePublicEgressIP(%s): %v", addr, err)
			}
			if !tt.want && !errors.Is(err, ErrNonPublicEgressIP) {
				t.Fatalf("ValidatePublicEgressIP(%s) error = %v, want ErrNonPublicEgressIP", addr, err)
			}
		})
	}

	if IsPublicEgressIP(netip.Addr{}) {
		t.Fatal("invalid address passed the public-egress perimeter")
	}
	if IsPublicEgressIP(netip.MustParseAddr("fe80::1").WithZone("eth0")) {
		t.Fatal("zoned address passed the public-egress perimeter")
	}
}

func runStrictProxyRequest(t *testing.T, p *Proxy, request string) string {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		_ = p.handleConn(server)
		close(done)
	}()

	if _, err := client.Write([]byte(request)); err != nil {
		_ = client.Close()
		t.Fatalf("write proxy request: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = client.Close()
		t.Fatalf("set proxy response deadline: %v", err)
	}
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		_ = client.Close()
		t.Fatalf("read proxy response: %v", err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy handler did not exit")
	}
	return string(buf[:n])
}

func openStrictHTTPSTunnel(t *testing.T, p *Proxy, authority string) (net.Conn, *bufio.Reader, <-chan error) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- p.handleConn(server)
	}()

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	request := "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
	if err := writeAll(client, []byte(request)); err != nil {
		_ = client.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		_ = client.Close()
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200 Connection Established") {
		_ = client.Close()
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = client.Close()
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, reader, done
}

func strictSNIProxyForTest(emitter *strictAuditTestEmitter) *Proxy {
	p := &Proxy{
		sessionID:             "s",
		emit:                  emitter,
		strictPublicEgress:    true,
		tlsClientHelloTimeout: 250 * time.Millisecond,
	}
	p.lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	return p
}

func waitStrictHTTPSHandler(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("strict HTTPS handler: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("strict HTTPS handler did not exit")
	}
}

func strictSNIDenialEvent(t *testing.T, emitter *strictAuditTestEmitter) types.Event {
	t.Helper()
	_, events := emitter.snapshot()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "net_connect" {
			if events[i].Policy == nil || events[i].Policy.EffectiveDecision != types.DecisionDeny {
				t.Fatalf("SNI event was not a denial: %+v", events[i])
			}
			if events[i].Policy.Rule != "strict-public-egress-sni-binding" {
				t.Fatalf("SNI denial rule = %q", events[i].Policy.Rule)
			}
			return events[i]
		}
	}
	t.Fatalf("missing strict SNI denial event: %+v", events)
	return types.Event{}
}

func runStrictSNIDenial(t *testing.T, authority string, hello []byte, helloTimeout time.Duration) types.Event {
	t.Helper()
	emitter := &strictAuditTestEmitter{}
	p := strictSNIProxyForTest(emitter)
	if helloTimeout > 0 {
		p.tlsClientHelloTimeout = helloTimeout
	}
	var dialed atomic.Bool
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected strict SNI dial")
	}

	client, _, done := openStrictHTTPSTunnel(t, p, authority)
	if hello != nil {
		if err := writeAll(client, hello); err != nil {
			_ = client.Close()
			t.Fatalf("write ClientHello: %v", err)
		}
	}
	waitStrictHTTPSHandler(t, done)
	_ = client.Close()
	if dialed.Load() {
		t.Fatal("strict SNI denial dialed upstream")
	}
	return strictSNIDenialEvent(t, emitter)
}

func TestHandleConnectStrictSNIMatchForwardsOriginalClientHelloAfterAudit(t *testing.T) {
	emitter := &strictAuditTestEmitter{}
	p := strictSNIProxyForTest(emitter)
	type dialObservation struct {
		network string
		address string
		peer    net.Conn
		calls   []string
	}
	dialed := make(chan dialObservation, 1)
	p.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		proxyUpstream, testUpstream := net.Pipe()
		calls, _ := emitter.snapshot()
		dialed <- dialObservation{network: network, address: address, peer: testUpstream, calls: calls}
		return proxyUpstream, nil
	}

	client, _, done := openStrictHTTPSTunnel(t, p, "Example.Test.:443")
	select {
	case observation := <-dialed:
		_ = observation.peer.Close()
		_ = client.Close()
		t.Fatal("strict proxy dialed before receiving ClientHello")
	case <-time.After(20 * time.Millisecond):
	}

	hello := buildClientHello("example.test")
	if err := writeAll(client, hello); err != nil {
		_ = client.Close()
		t.Fatalf("write ClientHello: %v", err)
	}

	var observation dialObservation
	select {
	case observation = <-dialed:
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("matching SNI did not reach pinned dial")
	}
	if observation.network != "tcp" || observation.address != "8.8.8.8:443" {
		t.Fatalf("dial = %s %s", observation.network, observation.address)
	}
	if len(observation.calls) < 3 {
		t.Fatalf("calls before dial = %v", observation.calls)
	}
	if got := observation.calls[len(observation.calls)-3:]; strings.Join(got, "|") != "append:net_connect|flush|publish:net_connect" {
		t.Fatalf("calls before dial = %v", observation.calls)
	}
	if err := observation.peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	forwarded := make([]byte, len(hello))
	if _, err := io.ReadFull(observation.peer, forwarded); err != nil {
		t.Fatalf("read forwarded ClientHello: %v", err)
	}
	if !bytes.Equal(forwarded, hello) {
		t.Fatal("matching ClientHello was modified")
	}

	_ = observation.peer.Close()
	_ = client.Close()
	waitStrictHTTPSHandler(t, done)
}

func TestHandleConnectStrictSNIMismatchDeniesWithoutDial(t *testing.T) {
	event := runStrictSNIDenial(t, "api.example:443", buildClientHello("other.example"), 0)
	if event.Fields["tls_sni_expected"] != "api.example" || event.Fields["tls_sni"] != "other.example" {
		t.Fatalf("SNI mismatch fields = %+v", event.Fields)
	}
}

func TestHandleConnectStrictMissingSNIDeniesWithoutDial(t *testing.T) {
	event := runStrictSNIDenial(t, "api.example:443", buildClientHelloNoSNI(), 0)
	if !strings.Contains(event.Fields["proxy_error"].(string), ErrNoSNIExtension.Error()) {
		t.Fatalf("missing-SNI audit fields = %+v", event.Fields)
	}
}

func TestHandleConnectStrictMalformedSNIDeniesWithoutDial(t *testing.T) {
	hello := buildClientHello("api.example")
	loc, err := findSNI(hello)
	if err != nil {
		t.Fatal(err)
	}
	malformed := append([]byte(nil), hello...)
	binary.BigEndian.PutUint16(malformed[loc.sniListLenOffset:], uint16(loc.origListLen+1))
	event := runStrictSNIDenial(t, "api.example:443", malformed, 0)
	if !strings.Contains(event.Fields["proxy_error"].(string), ErrMalformedSNI.Error()) {
		t.Fatalf("malformed-SNI audit fields = %+v", event.Fields)
	}
}

func TestHandleConnectStrictECHOuterSNIMismatchDeniesWithoutDial(t *testing.T) {
	echData := []byte{
		0x00,       // outer ClientHello
		0x00, 0x01, // KDF ID
		0x00, 0x01, // AEAD ID
		0x01,       // config ID
		0x00, 0x00, // empty encapsulated key
		0x00, 0x00, // empty payload
	}
	echExtension := []byte{0xfe, 0x0d, 0x00, byte(len(echData))}
	echExtension = append(echExtension, echData...)
	event := runStrictSNIDenial(t, "secret.example:443", buildClientHello("public.example", echExtension), 0)
	if event.Fields["tls_ech"] != true || !strings.Contains(event.Fields["proxy_error"].(string), "ECH outer SNI") {
		t.Fatalf("ECH outer-name audit fields = %+v", event.Fields)
	}
}

func TestHandleConnectStrictClientHelloTimeoutDeniesWithoutDial(t *testing.T) {
	event := runStrictSNIDenial(t, "api.example:443", nil, 25*time.Millisecond)
	if !strings.Contains(event.Fields["proxy_error"].(string), "timeout") {
		t.Fatalf("timeout audit fields = %+v", event.Fields)
	}
}

func TestStrictPublicEgressRejectsLocalSocketTargets(t *testing.T) {
	p := &Proxy{strictPublicEgress: true}
	_, _, err := p.prepareStrictPublicDialTarget(context.Background(), "command", resolvedConnectDialTarget{
		Network: "unix", Address: "/run/private/service.sock",
	})
	if err == nil || !strings.Contains(err.Error(), "non-TCP") {
		t.Fatalf("local socket target error = %v, want non-TCP rejection", err)
	}
}

func TestHandleConnectStrictAuditAppendAndFlushPrecedeDial(t *testing.T) {
	emitter := &strictAuditTestEmitter{}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		emitter.record("dial:" + network + ":" + address)
		return nil, errors.New("dial stopped by test")
	}

	response := runStrictProxyRequest(t, p, "CONNECT 8.8.8.8:8443 HTTP/1.1\r\nHost: 8.8.8.8:8443\r\n\r\n")
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Fatalf("response = %q, want dial failure", response)
	}
	calls, _ := emitter.snapshot()
	want := []string{"append:net_connect", "flush", "publish:net_connect", "dial:tcp:8.8.8.8:8443"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

func TestHandleConnectStrictAuditFailurePreventsDial(t *testing.T) {
	auditErr := errors.New("audit unavailable")
	emitter := &strictAuditTestEmitter{appendError: map[string]error{"net_connect": auditErr}}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		emitter.record("dial")
		return nil, errors.New("unexpected dial")
	}

	response := runStrictProxyRequest(t, p, "CONNECT 8.8.8.8:8443 HTTP/1.1\r\nHost: 8.8.8.8:8443\r\n\r\n")
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Fatalf("response = %q, want audit failure", response)
	}
	calls, _ := emitter.snapshot()
	if got, want := strings.Join(calls, "|"), "append:net_connect"; got != want {
		t.Fatalf("calls = %v, want append only", calls)
	}
}

func TestHandleConnectStrictAuditFlushFailurePreventsDial(t *testing.T) {
	emitter := &strictAuditTestEmitter{flushError: errors.New("sync failed")}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		emitter.record("dial")
		return nil, errors.New("unexpected dial")
	}

	_ = runStrictProxyRequest(t, p, "CONNECT 8.8.8.8:8443 HTTP/1.1\r\nHost: 8.8.8.8:8443\r\n\r\n")
	calls, _ := emitter.snapshot()
	if got, want := strings.Join(calls, "|"), "append:net_connect|flush"; got != want {
		t.Fatalf("calls = %v, want append and failed flush only", calls)
	}
}

func TestHandleConnectDefaultModeKeepsBestEffortAudit(t *testing.T) {
	emitter := &strictAuditTestEmitter{appendError: map[string]error{"net_connect": errors.New("audit unavailable")}}
	p := &Proxy{sessionID: "s", emit: emitter}
	p.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		emitter.record("dial:" + network + ":" + address)
		return nil, errors.New("dial stopped by test")
	}

	_ = runStrictProxyRequest(t, p, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	calls, _ := emitter.snapshot()
	want := []string{"append:net_connect", "publish:net_connect", "dial:tcp:127.0.0.1:443"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("default-mode calls = %v, want legacy best-effort order %v", calls, want)
	}
}

func TestHandleConnectStrictPerimeterRejectsLoopback(t *testing.T) {
	emitter := &strictAuditTestEmitter{}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		emitter.record("dial")
		return nil, errors.New("unexpected dial")
	}

	response := runStrictProxyRequest(t, p, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("response = %q, want strict perimeter rejection", response)
	}
	calls, events := emitter.snapshot()
	for _, call := range calls {
		if call == "dial" || strings.HasPrefix(call, "dial:") {
			t.Fatalf("strict perimeter attempted dial: %v", calls)
		}
	}
	if len(events) == 0 || events[0].Policy == nil || events[0].Policy.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("strict perimeter deny event missing: %+v", events)
	}
	if events[0].Policy.Rule != "strict-public-egress-perimeter" {
		t.Fatalf("deny rule = %q, want strict perimeter rule", events[0].Policy.Rule)
	}
}

func TestHandleConnectStrictPerimeterRejectsResolvedPrivateIP(t *testing.T) {
	emitter := &strictAuditTestEmitter{}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}, nil
	}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		emitter.record("dial")
		return nil, errors.New("unexpected dial")
	}

	response := runStrictProxyRequest(t, p, "CONNECT private.example:443 HTTP/1.1\r\nHost: private.example:443\r\n\r\n")
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("response = %q, want strict perimeter rejection", response)
	}
	calls, events := emitter.snapshot()
	for _, call := range calls {
		if call == "dial" || strings.HasPrefix(call, "dial:") {
			t.Fatalf("strict perimeter attempted dial: %v", calls)
		}
	}
	var connectEvent *types.Event
	for i := range events {
		if events[i].Type == "net_connect" {
			connectEvent = &events[i]
			break
		}
	}
	if connectEvent == nil || connectEvent.Fields["rejected_ip"] != "10.20.30.40" {
		t.Fatalf("resolved-IP rejection event missing: %+v", events)
	}
}

func TestStrictProxyMultiAnswerPolicyUsesExactSelectedIP(t *testing.T) {
	engine, err := policy.NewEngine(&policy.Policy{NetworkRules: []policy.NetworkRule{
		{Name: "deny-selected-range", CIDRs: []string{"8.8.8.0/24"}, Ports: []int{8443}, Decision: "deny"},
		{Name: "allow-hostname", Domains: []string{"multi.example"}, Ports: []int{8443}, Decision: "allow"},
	}}, true, true)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		answers    []net.IPAddr
		wantStatus string
		wantDial   string
	}{
		{
			name:       "first answer denied even though later answer is allowed",
			answers:    []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("1.1.1.1")}},
			wantStatus: "403 Forbidden",
		},
		{
			name:       "first answer allowed and pinned despite later denied answer",
			answers:    []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}, {IP: net.ParseIP("8.8.8.8")}},
			wantStatus: "502 Bad Gateway",
			wantDial:   "1.1.1.1:8443",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			emitter := &strictAuditTestEmitter{}
			p := &Proxy{sessionID: "s", policy: engine, emit: emitter, strictPublicEgress: true}
			lookups := 0
			p.lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
				lookups++
				if host != "multi.example" {
					t.Fatalf("lookup host = %q", host)
				}
				return test.answers, nil
			}
			dialed := ""
			p.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" {
					t.Fatalf("dial network = %q", network)
				}
				dialed = address
				return nil, errors.New("dial stopped by test")
			}

			response := runStrictProxyRequest(t, p, "CONNECT multi.example:8443 HTTP/1.1\r\nHost: multi.example:8443\r\n\r\n")
			if !strings.Contains(response, test.wantStatus) {
				t.Fatalf("response = %q, want %s", response, test.wantStatus)
			}
			if lookups != 1 {
				t.Fatalf("resolver calls = %d, want exactly one", lookups)
			}
			if dialed != test.wantDial {
				t.Fatalf("dialed = %q, want exact selected target %q", dialed, test.wantDial)
			}
		})
	}
}

func TestStrictProxyHostnameDenyDoesNotResolve(t *testing.T) {
	engine, err := policy.NewEngine(&policy.Policy{NetworkRules: []policy.NetworkRule{
		{Name: "deny-hostname", Domains: []string{"denied.example"}, Ports: []int{443}, Decision: "deny"},
		{Name: "allow-rest", Domains: []string{"*"}, Decision: "allow"},
	}}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{sessionID: "s", policy: engine, emit: &strictAuditTestEmitter{}, strictPublicEgress: true}
	p.lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("hostname-denied strict request attempted DNS")
		return nil, nil
	}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("hostname-denied strict request attempted dial")
		return nil, nil
	}
	response := runStrictProxyRequest(t, p, "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
	if !strings.Contains(response, "403 Forbidden") {
		t.Fatalf("response = %q", response)
	}
}

func TestProxyStrictHTTPAuditFailurePreventsDial(t *testing.T) {
	emitter := &strictAuditTestEmitter{appendError: map[string]error{"net_connect": errors.New("audit unavailable")}}
	p := &Proxy{sessionID: "s", emit: emitter, strictPublicEgress: true}
	p.dialContext = func(context.Context, string, string) (net.Conn, error) {
		emitter.record("dial")
		return nil, errors.New("unexpected dial")
	}

	response := runStrictProxyRequest(t, p, "GET http://8.8.8.8/ HTTP/1.1\r\nHost: 8.8.8.8\r\n\r\n")
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Fatalf("response = %q, want audit failure", response)
	}
	calls, _ := emitter.snapshot()
	want := []string{"append:net_http_request", "publish:net_http_request", "append:net_connect"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("HTTP calls = %v, want %v", calls, want)
	}
}
