package externalrunner

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestCompileHostEgressPolicyUsesExactSnapshotAndEnforcesApprovals(t *testing.T) {
	data := []byte(`version: 1
name: host-egress-test
network_rules:
  - name: allow-example
    domains: [allowed.example]
    ports: [443]
    decision: allow
  - name: approve-example
    domains: [approve.example]
    ports: [443]
    decision: approve
  - name: deny-rest
    domains: ["*"]
    decision: deny
`)
	path := filepath.Join(t.TempDir(), "host-egress.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	spec := HostEgressSpec{PolicyFile: path, PolicySHA256: digest(data)}
	engine, err := compileHostEgressPolicy(spec)
	if err != nil {
		t.Fatal(err)
	}
	allowed := engine.CheckNetwork("allowed.example", 443)
	if allowed.PolicyDecision != types.DecisionAllow || allowed.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("allow decision = %+v", allowed)
	}
	approval := engine.CheckNetwork("approve.example", 443)
	if approval.PolicyDecision != types.DecisionApprove || approval.EffectiveDecision != types.DecisionApprove || approval.Approval == nil || !approval.Approval.Required {
		t.Fatalf("approval was not compiled in enforced mode: %+v", approval)
	}

	if err := os.WriteFile(path, append(append([]byte(nil), data...), []byte("\n# changed")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := compileHostEgressPolicy(spec); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("changed policy snapshot error = %v", err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := compileHostEgressPolicy(spec); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("writable policy snapshot error = %v", err)
	}
}

func TestHostEgressApproveRuleFailsClosedWithoutApprovalManager(t *testing.T) {
	data := []byte(`version: 1
name: host-egress-approve
network_rules:
  - name: approve-example
    domains: [approve.example]
    ports: [443]
    decision: approve
`)
	path := filepath.Join(t.TempDir(), "host-egress.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := compileHostEgressPolicy(HostEgressSpec{PolicyFile: path, PolicySHA256: digest(data)})
	if err != nil {
		t.Fatal(err)
	}
	audit, err := openHostNetworkAudit(filepath.Join(t.TempDir(), HostEgressAuditName))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		_ = audit.Close()
		t.Skipf("IPv4 loopback unavailable: %v", err)
	}
	proxy, _, err := netmonitor.StartProxyWithOptions(netmonitor.ProxyStartOptions{Listener: listener, StrictPublicEgress: true}, "session-approve", nil, engine, nil, audit)
	if err != nil {
		_ = listener.Close()
		_ = audit.Close()
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		_ = proxy.Close()
		_ = audit.Close()
		t.Fatal(err)
	}
	_, _ = client.Write([]byte("CONNECT approve.example:443 HTTP/1.1\r\nHost: approve.example:443\r\n\r\n"))
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	status, readErr := bufio.NewReader(client).ReadString('\n')
	_ = client.Close()
	proxyErr := proxy.Close()
	auditErr := audit.Close()
	if readErr != nil || !strings.Contains(status, "403 Forbidden") {
		t.Fatalf("approve response = %q, %v", status, readErr)
	}
	if proxyErr != nil || auditErr != nil {
		t.Fatalf("close proxy=%v audit=%v", proxyErr, auditErr)
	}
}

func TestHostEgressBrokerSignalsFatalAuditHealth(t *testing.T) {
	audit, err := openHostNetworkAudit(filepath.Join(t.TempDir(), HostEgressAuditName))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		_ = audit.Close()
		t.Skipf("IPv4 loopback unavailable: %v", err)
	}
	proxy, _, err := netmonitor.StartProxyWithOptions(netmonitor.ProxyStartOptions{Listener: listener, StrictPublicEgress: true}, "session-health", nil, nil, nil, audit)
	if err != nil {
		_ = listener.Close()
		_ = audit.Close()
		t.Fatal(err)
	}
	broker, err := newRunningHostEgressBroker(proxy, audit)
	if err != nil {
		_ = proxy.Close()
		_ = audit.Close()
		t.Fatal(err)
	}
	if err := audit.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := audit.FlushSync(context.Background()); err == nil {
		t.Fatal("forced audit fsync failure returned nil")
	}
	select {
	case <-broker.Done():
		if broker.Err() == nil || !strings.Contains(broker.Err().Error(), "audit") {
			t.Fatalf("broker health error = %v", broker.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not signal fatal audit health")
	}
}

func TestHostNetworkAuditWritesDurableJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), HostEgressAuditName)
	audit, err := openHostNetworkAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	event := types.Event{ID: "event-1", Type: "net_connect", SessionID: "session-test"}
	if err := audit.AppendEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := audit.FlushSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d: %q", len(lines), data)
	}
	var decoded types.Event
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != event.ID || decoded.Type != event.Type || decoded.SessionID != event.SessionID {
		t.Fatalf("audit event = %+v", decoded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %o, want 0600", info.Mode().Perm())
	}
	if err := audit.AppendEvent(context.Background(), event); err == nil {
		t.Fatal("closed host audit accepted an event")
	}
}

func TestHostNetworkAuditBoundsBytesAndLatchesStorageFailures(t *testing.T) {
	event := types.Event{ID: strings.Repeat("x", 128), Type: "net_connect", SessionID: "session-test"}
	audit, err := openHostNetworkAuditWithLimit(filepath.Join(t.TempDir(), HostEgressAuditName), 32)
	if err != nil {
		t.Fatal(err)
	}
	firstErr := audit.AppendEvent(context.Background(), event)
	if firstErr == nil || !strings.Contains(firstErr.Error(), "limit") {
		t.Fatalf("bounded audit error = %v", firstErr)
	}
	select {
	case <-audit.Done():
	default:
		t.Fatal("bounded audit failure did not latch Done")
	}
	if secondErr := audit.AppendEvent(context.Background(), types.Event{}); secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Fatalf("latched error = %v, want %v", secondErr, firstErr)
	}
	_ = audit.Close()

	audit, err = openHostNetworkAudit(filepath.Join(t.TempDir(), HostEgressAuditName))
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.file.Close(); err != nil {
		t.Fatal(err)
	}
	firstErr = audit.AppendEvent(context.Background(), event)
	if firstErr == nil || !strings.Contains(firstErr.Error(), "append") {
		t.Fatalf("write failure = %v", firstErr)
	}
	if secondErr := audit.AppendEvent(context.Background(), types.Event{}); secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Fatalf("latched write error = %v, want %v", secondErr, firstErr)
	}
	_ = audit.Close()

	audit, err = openHostNetworkAudit(filepath.Join(t.TempDir(), HostEgressAuditName))
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.file.Close(); err != nil {
		t.Fatal(err)
	}
	firstErr = audit.FlushSync(context.Background())
	if firstErr == nil || !strings.Contains(firstErr.Error(), "sync") {
		t.Fatalf("fsync failure = %v", firstErr)
	}
	if audit.Err() == nil || audit.Err().Error() != firstErr.Error() {
		t.Fatalf("latched fsync error = %v, want %v", audit.Err(), firstErr)
	}
	select {
	case <-audit.Done():
	default:
		t.Fatal("fsync failure did not latch Done")
	}
	_ = audit.Close()
}
