//go:build linux

package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/nethelper"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

type strictProxyTunnelResult struct {
	conn net.Conn
	err  error
}

func openStrictProxyTunnel(proxyURL, target string) <-chan strictProxyTunnelResult {
	result := make(chan strictProxyTunnelResult, 1)
	go func() {
		u, err := url.Parse(proxyURL)
		if err != nil {
			result <- strictProxyTunnelResult{err: err}
			return
		}
		conn, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
		if err != nil {
			result <- strictProxyTunnelResult{err: err}
			return
		}
		if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
			_ = conn.Close()
			result <- strictProxyTunnelResult{err: err}
			return
		}
		reader := bufio.NewReader(conn)
		status, err := reader.ReadString('\n')
		if err == nil && !strings.Contains(status, " 200 ") {
			err = fmt.Errorf("proxy status %q", strings.TrimSpace(status))
		}
		for err == nil {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				err = readErr
				break
			}
			if line == "\r\n" {
				break
			}
		}
		if err != nil {
			_ = conn.Close()
			result <- strictProxyTunnelResult{err: err}
			return
		}
		result <- strictProxyTunnelResult{conn: conn}
	}()
	return result
}

func waitForStrictProxyApprovals(t *testing.T, manager *approvals.Manager, want int) []approvals.Request {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		pending := manager.ListPending()
		if len(pending) == want {
			return pending
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending proxy approvals = %d, want %d", len(pending), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestChildExecutionLanes_StrictCommandProxiesKeepImmutableAttribution(t *testing.T) {
	app, sess, _ := newChildLaneTest(t, 2)
	app.cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"

	engine, err := policy.NewEngine(&policy.Policy{
		Version: 1,
		Name:    "strict-command-proxy-attribution",
		NetworkRules: []policy.NetworkRule{{
			Name: "approve-all-proxy-connects", Domains: []string{"**"}, Decision: "approve",
		}},
	}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	sess.SetPolicyEngine(engine)
	emitter := storeEmitter{store: app.store, broker: app.broker}
	approvalManager := approvals.New("remote", 5*time.Second, emitter)
	app.approvals = approvalManager

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			conn, acceptErr := upstream.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()

	proxyA, err := app.startCommandExplicitProxy(context.Background(), sess, "cmd-strict-a")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyA.Close()
	proxyB, err := app.startCommandExplicitProxy(context.Background(), sess, "cmd-strict-b")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyB.Close()
	if proxyA.URL() == proxyB.URL() {
		t.Fatalf("command proxies shared endpoint %q", proxyA.URL())
	}

	tunnelAResult := openStrictProxyTunnel(proxyA.URL(), upstream.Addr().String())
	tunnelBResult := openStrictProxyTunnel(proxyB.URL(), upstream.Addr().String())
	pending := waitForStrictProxyApprovals(t, approvalManager, 2)
	seenPending := map[string]bool{}
	for _, request := range pending {
		seenPending[request.CommandID] = true
		if !approvalManager.Resolve(request.ID, true, "test approval") {
			t.Fatalf("resolve approval %s", request.ID)
		}
	}
	if !seenPending["cmd-strict-a"] || !seenPending["cmd-strict-b"] {
		t.Fatalf("pending approval attribution = %#v", seenPending)
	}

	tunnelA := <-tunnelAResult
	if tunnelA.err != nil {
		t.Fatal(tunnelA.err)
	}
	defer tunnelA.conn.Close()
	tunnelB := <-tunnelBResult
	if tunnelB.err != nil {
		t.Fatal(tunnelB.err)
	}
	defer tunnelB.conn.Close()

	// A session-global value changing while both tunnels remain open must not
	// alter either command proxy's terminal attribution.
	sess.SetCurrentCommandID("cmd-wrong-session-singleton")
	if err := proxyB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxyA.Close(); err != nil {
		t.Fatal(err)
	}
	_ = upstream.Close()
	<-upstreamDone

	persisted, err := app.store.QueryEvents(context.Background(), types.EventQuery{SessionID: sess.ID, Limit: 200, Asc: true})
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]map[string]bool{
		"cmd-strict-a": {},
		"cmd-strict-b": {},
	}
	proxyEvent := map[string]bool{
		"net_proxy_started": true, "approval_requested": true, "approval_resolved": true,
		"net_connect": true, "net_close": true, "net_proxy_stopped": true,
	}
	for _, event := range persisted {
		if !proxyEvent[event.Type] {
			continue
		}
		byType, ok := required[event.CommandID]
		if !ok {
			t.Fatalf("proxy event %s used mutable/wrong command attribution %q", event.Type, event.CommandID)
		}
		byType[event.Type] = true
	}
	for commandID, byType := range required {
		for eventType := range proxyEvent {
			if !byType[eventType] {
				t.Errorf("command %s missing attributed %s event", commandID, eventType)
			}
		}
	}
}

type strictConcurrentCgroupManager struct {
	root string
}

func (m *strictConcurrentCgroupManager) Apply(name string, _ int, _ limits.CgroupV2Limits) (*limits.CgroupV2, error) {
	// A symlink models cgroupfs virtual control files: Close can remove the
	// cgroup entry even though cgroup.events is visible through it.
	target := filepath.Join(m.root, "targets", name)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(target, "cgroup.events"), []byte("populated 0\n"), 0o600); err != nil {
		return nil, err
	}
	path := filepath.Join(m.root, name)
	if err := os.Symlink(target, path); err != nil {
		return nil, err
	}
	return &limits.CgroupV2{Path: path}, nil
}

func (m *strictConcurrentCgroupManager) Probe() *limits.CgroupProbeResult {
	return &limits.CgroupProbeResult{Mode: limits.ModeNested, OwnCgroup: m.root}
}

type strictConcurrentNethelperBackend struct {
	mu sync.Mutex

	nextID       uint64
	register     map[string]nethelper.RegisterSessionCgroupRequest
	update       map[string]nethelper.UpdatePolicyMapRequest
	cleanupOrder []string
}

func newStrictConcurrentNethelperBackend() *strictConcurrentNethelperBackend {
	return &strictConcurrentNethelperBackend{
		nextID: 100, register: make(map[string]nethelper.RegisterSessionCgroupRequest), update: make(map[string]nethelper.UpdatePolicyMapRequest),
	}
}

func (b *strictConcurrentNethelperBackend) RegisterSessionCgroup(_ context.Context, _ nethelper.PeerInfo, req nethelper.RegisterSessionCgroupRequest) (nethelper.RegisterSessionCgroupResponse, error) {
	b.mu.Lock()
	b.nextID++
	cgroupID := b.nextID
	b.register[req.RequestID] = req
	b.mu.Unlock()
	return nethelper.RegisterSessionCgroupResponse{
		OK: true, Tier: req.Tier.Normalized(), Mode: req.Mode.Normalized(), CgroupID: cgroupID,
		RegistrationID: "registration-" + req.RequestID,
		PinPath:        filepath.Join(string(filepath.Separator), "pins", req.RequestID),
	}, nil
}

func (b *strictConcurrentNethelperBackend) UpdatePolicyMap(_ context.Context, _ nethelper.PeerInfo, req nethelper.UpdatePolicyMapRequest) (nethelper.UpdatePolicyMapResponse, error) {
	b.mu.Lock()
	b.update[req.RequestID] = req
	b.mu.Unlock()
	return nethelper.UpdatePolicyMapResponse{OK: true, DefaultDeny: req.DefaultDeny, AllowEntries: len(req.Allow), DenyEntries: len(req.Deny)}, nil
}

func (b *strictConcurrentNethelperBackend) CleanupSession(_ context.Context, _ nethelper.PeerInfo, req nethelper.CleanupSessionRequest) (nethelper.CleanupSessionResponse, error) {
	b.mu.Lock()
	b.cleanupOrder = append(b.cleanupOrder, req.RequestID)
	b.mu.Unlock()
	return nethelper.CleanupSessionResponse{OK: true}, nil
}

func (b *strictConcurrentNethelperBackend) requests(commandID string) (nethelper.RegisterSessionCgroupRequest, nethelper.UpdatePolicyMapRequest) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.register[commandID], b.update[commandID]
}

func (b *strictConcurrentNethelperBackend) cleaned() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.cleanupOrder...)
}

func startStrictConcurrentNethelper(t *testing.T, backend *strictConcurrentNethelperBackend) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "nethelper.sock")
	listener, err := nethelper.ListenUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := nethelper.NewServer(backend, nethelper.AllowAuthorizer{})
	go func() { _ = server.ServeListener(ctx, listener) }()
	return socketPath
}

func endpointPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestChildExecutionLanes_StrictAttachmentsInterleaveAndReverseCleanup(t *testing.T) {
	app, sess, _ := newChildLaneTest(t, 2)
	app.cfg.Sandbox.Cgroups.Enabled = true
	app.cfg.Sandbox.Network.Enabled = true
	app.cfg.Sandbox.Network.EBPF.Enabled = true
	app.cfg.Sandbox.Network.EBPF.Enforce = true
	app.cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"
	app.cgroupMgr = &strictConcurrentCgroupManager{root: t.TempDir()}

	backend := newStrictConcurrentNethelperBackend()
	socketPath := startStrictConcurrentNethelper(t, backend)
	app.nethelperBinding = newNethelperBindingState(socketPath, "", "", "strict-test-credential")

	proxyA, err := app.startCommandExplicitProxy(context.Background(), sess, "cmd-strict-a")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyA.Close()
	proxyB, err := app.startCommandExplicitProxy(context.Background(), sess, "cmd-strict-b")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyB.Close()

	emitter := storeEmitter{store: app.store, broker: app.broker}
	endpointsA := &networkProxyEndpoints{ProxyURL: proxyA.URL()}
	cleanupA, err := applyCgroupV2WithProxyEndpoints(context.Background(), emitter, app, sess.ID, "cmd-strict-a", 1001, policy.Limits{}, nil, app.policyEngineFor(sess), endpointsA)
	if err != nil {
		t.Fatal(err)
	}
	// Keep A attached while B traverses registration/update. This is the
	// overlap that previously overwrote the singleton attachment.
	endpointsB := &networkProxyEndpoints{ProxyURL: proxyB.URL()}
	cleanupB, err := applyCgroupV2WithProxyEndpoints(context.Background(), emitter, app, sess.ID, "cmd-strict-b", 1002, policy.Limits{}, nil, app.policyEngineFor(sess), endpointsB)
	if err != nil {
		t.Fatal(err)
	}

	report := sess.NetworkEnforcement()
	if report == nil || len(report.Attachments) != 2 {
		t.Fatalf("concurrent attachment report = %+v, want two attachments", report)
	}
	attachmentEndpoints := map[string]string{}
	for _, attachment := range report.Attachments {
		attachmentEndpoints[attachment.CommandID] = attachment.ProxyEndpointID
	}
	for commandID, commandProxy := range map[string]*commandExplicitProxy{"cmd-strict-a": proxyA, "cmd-strict-b": proxyB} {
		registration, update := backend.requests(commandID)
		wantPort := endpointPort(t, commandProxy.URL())
		if registration.Proxy == nil || registration.Proxy.Host != "127.0.0.1" || registration.Proxy.Port != wantPort {
			t.Fatalf("%s registration proxy = %+v, want exact command endpoint port %d", commandID, registration.Proxy, wantPort)
		}
		if !update.DefaultDeny || update.Proxy == nil || update.Proxy.Port != wantPort || len(update.Allow) != 1 {
			t.Fatalf("%s strict update = %+v", commandID, update)
		}
		allow := update.Allow[0]
		if allow.IP != "127.0.0.1" || allow.CIDR != "" || allow.Port != wantPort || allow.Protocol != nethelper.TransportProtocolTCP {
			t.Fatalf("%s allow entry = %+v, want only exact command proxy", commandID, allow)
		}
		if attachmentEndpoints[commandID] != net.JoinHostPort("127.0.0.1", fmt.Sprint(wantPort)) {
			t.Fatalf("%s attachment endpoint = %q", commandID, attachmentEndpoints[commandID])
		}
	}

	// Reverse command cleanup. Close B's proxy before its attachment, while A
	// uses the production attachment-before-proxy order; both orders fail closed.
	if err := proxyB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cleanupB(); err != nil {
		t.Fatal(err)
	}
	report = sess.NetworkEnforcement()
	if report == nil || len(report.Attachments) != 1 || report.Attachments[0].CommandID != "cmd-strict-a" {
		t.Fatalf("report after B cleanup = %+v, want only A", report)
	}
	if err := cleanupA(); err != nil {
		t.Fatal(err)
	}
	if err := proxyA.Close(); err != nil {
		t.Fatal(err)
	}
	report = sess.NetworkEnforcement()
	if report != nil && len(report.Attachments) != 0 {
		t.Fatalf("attachments after reverse cleanup = %+v", report.Attachments)
	}
	if got := backend.cleaned(); len(got) != 2 || got[0] != "cmd-strict-b" || got[1] != "cmd-strict-a" {
		t.Fatalf("helper cleanup order = %v, want [cmd-strict-b cmd-strict-a]", got)
	}
}
