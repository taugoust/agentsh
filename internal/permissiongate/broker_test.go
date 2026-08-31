package permissiongate

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recordingAudit struct {
	mu      sync.Mutex
	records []AuditRecord
	err     error
}

func (a *recordingAudit) Append(record AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.records = append(a.records, record)
	return nil
}

func (a *recordingAudit) snapshot() []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditRecord(nil), a.records...)
}

func startTestBroker(t *testing.T, audit AuditAppender) (net.Conn, <-chan error) {
	t.Helper()
	server, client := net.Pipe()
	result := make(chan error, 1)
	go func() {
		result <- NewBroker(server, audit, "test-run").Serve()
		_ = server.Close()
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client, result
}

func sendTestFrame(t *testing.T, connection net.Conn, message any) {
	t.Helper()
	if err := writeFrame(connection, message); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

func readTestFrame[T any](t *testing.T, reader *frameReader) T {
	t.Helper()
	frame, err := reader.read()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var message T
	if err := json.Unmarshal(frame, &message); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return message
}

func testHandshake(t *testing.T, connection net.Conn, reader *frameReader) {
	t.Helper()
	sendTestFrame(t, connection, HelloRequest{V: ProtocolVersion, Type: messageHello, Client: "pi-permission-gate"})
	response := readTestFrame[HelloResponse](t, reader)
	if response.V != ProtocolVersion || response.Type != messageHello || response.Service != "agentsh-permission-gate" {
		t.Fatalf("hello response = %#v", response)
	}
}

func TestPermissionGateBrokerAllowsHarmlessBashOnlyAfterAudit(t *testing.T) {
	audit := &recordingAudit{}
	connection, result := startTestBroker(t, audit)
	reader := newFrameReader(connection)
	testHandshake(t, connection, reader)

	request := AuthorizeRequest{
		V: ProtocolVersion, Type: messageAuthorize, ID: "request-1", Kind: "bash",
		Command: "printf hello", CWD: filepath.Join("workspace", "project"), ToolCallID: "tool-1",
	}
	sendTestFrame(t, connection, request)
	response := readTestFrame[DecisionResponse](t, reader)
	if response.Decision != "allow" || response.Prompt != nil || response.ID != request.ID {
		t.Fatalf("decision = %#v", response)
	}
	records := audit.snapshot()
	if len(records) != 1 || records[0].Decision != "allow" || records[0].CommandPreview != request.Command {
		t.Fatalf("audit records = %#v", records)
	}

	_ = connection.Close()
	if err := <-result; !errors.Is(err, ErrUnexpectedEOF) {
		t.Fatalf("Serve() error = %v, want unexpected EOF", err)
	}
}

func TestPermissionGateBrokerPromptResolutionIsAuditedBeforeComplete(t *testing.T) {
	audit := &recordingAudit{}
	connection, result := startTestBroker(t, audit)
	reader := newFrameReader(connection)
	testHandshake(t, connection, reader)

	request := AuthorizeRequest{
		V: ProtocolVersion, Type: messageAuthorize, ID: "request-dangerous", Kind: "bash",
		Command: "sudo rm -rf build", CWD: "workspace", ToolCallID: "tool-dangerous",
	}
	sendTestFrame(t, connection, request)
	decision := readTestFrame[DecisionResponse](t, reader)
	if decision.Decision != "prompt" || decision.Prompt == nil {
		t.Fatalf("decision = %#v, want prompt", decision)
	}
	if strings.Join(decision.Prompt.Labels, ",") != "recursive delete,sudo" {
		t.Fatalf("labels = %v", decision.Prompt.Labels)
	}
	if records := audit.snapshot(); len(records) != 0 {
		t.Fatalf("prompt was prematurely audited as terminal: %#v", records)
	}

	sendTestFrame(t, connection, ResolveRequest{
		V: ProtocolVersion, Type: messageResolve, ID: request.ID, Decision: "allow",
	})
	complete := readTestFrame[CompleteResponse](t, reader)
	if complete.Type != messageComplete || complete.Decision != "allow" || complete.ID != request.ID {
		t.Fatalf("complete = %#v", complete)
	}
	records := audit.snapshot()
	if len(records) != 1 || records[0].Decision != "allow" || len(records[0].Labels) != 2 {
		t.Fatalf("audit records = %#v", records)
	}

	_ = connection.Close()
	<-result
}

func TestPermissionGateBrokerDenyAndCancel(t *testing.T) {
	for _, test := range []struct {
		name   string
		finish any
		reason string
	}{
		{name: "deny", finish: ResolveRequest{V: ProtocolVersion, Type: messageResolve, ID: "request-1", Decision: "deny"}, reason: "denied by Pi user interface"},
		{name: "cancel", finish: CancelRequest{V: ProtocolVersion, Type: messageCancel, ID: "request-1", Reason: "caller aborted"}, reason: "caller aborted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			audit := &recordingAudit{}
			connection, result := startTestBroker(t, audit)
			reader := newFrameReader(connection)
			testHandshake(t, connection, reader)
			sendTestFrame(t, connection, AuthorizeRequest{
				V: ProtocolVersion, Type: messageAuthorize, ID: "request-1", Kind: "bash", Command: "ssh host",
			})
			_ = readTestFrame[DecisionResponse](t, reader)
			sendTestFrame(t, connection, test.finish)
			complete := readTestFrame[CompleteResponse](t, reader)
			if complete.Decision != "deny" || complete.Reason != test.reason {
				t.Fatalf("complete = %#v", complete)
			}
			records := audit.snapshot()
			if len(records) != 1 || records[0].Decision != "deny" || records[0].Reason != test.reason {
				t.Fatalf("records = %#v", records)
			}
			_ = connection.Close()
			<-result
		})
	}
}

func TestPermissionGateBrokerAuditFailureNeverAllows(t *testing.T) {
	auditFailure := errors.New("disk full")
	connection, result := startTestBroker(t, &recordingAudit{err: auditFailure})
	reader := newFrameReader(connection)
	testHandshake(t, connection, reader)
	sendTestFrame(t, connection, AuthorizeRequest{
		V: ProtocolVersion, Type: messageAuthorize, ID: "request-1", Kind: "bash", Command: "printf safe",
	})
	if err := <-result; !errors.Is(err, auditFailure) {
		t.Fatalf("Serve() error = %v, want audit failure", err)
	}
	if _, err := reader.read(); err == nil {
		t.Fatal("received allow after audit failure")
	}
}

func TestPermissionGateBrokerRejectsMalformedProtocolAndEOF(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{name: "malformed JSON", input: "{not-json}\n", want: ErrProtocol},
		{name: "unknown field", input: `{"v":1,"type":"hello","client":"pi-permission-gate","extra":true}` + "\n", want: ErrProtocol},
		{name: "duplicate field", input: `{"v":1,"v":1,"type":"hello","client":"pi-permission-gate"}` + "\n", want: ErrProtocol},
		{name: "unterminated", input: `{"v":1,"type":"hello","client":"pi-permission-gate"}`, want: ErrProtocol},
		{name: "wrong first message", input: `{"v":1,"type":"authorize","id":"x","kind":"bash","command":"true"}` + "\n", want: ErrProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, result := startTestBroker(t, &recordingAudit{})
			if _, err := connection.Write([]byte(test.input)); err != nil {
				t.Fatalf("write input: %v", err)
			}
			if !strings.HasSuffix(test.input, "\n") {
				_ = connection.Close()
			}
			if err := <-result; !errors.Is(err, test.want) {
				t.Fatalf("Serve() error = %v, want %v", err, test.want)
			}
		})
	}

	t.Run("EOF", func(t *testing.T) {
		connection, result := startTestBroker(t, &recordingAudit{})
		_ = connection.Close()
		if err := <-result; !errors.Is(err, ErrUnexpectedEOF) {
			t.Fatalf("Serve() error = %v, want unexpected EOF", err)
		}
	})
}

func TestPermissionGateProtocolFragmentedAndCoalescedFrames(t *testing.T) {
	audit := &recordingAudit{}
	connection, result := startTestBroker(t, audit)
	reader := newFrameReader(connection)
	hello, _ := json.Marshal(HelloRequest{V: ProtocolVersion, Type: messageHello, Client: "pi-permission-gate"})
	authorize, _ := json.Marshal(AuthorizeRequest{
		V: ProtocolVersion, Type: messageAuthorize, ID: "request-1", Kind: "bash", Command: "printf ok",
	})
	payload := append(append(append([]byte{}, hello...), '\n'), authorize...)
	payload = append(payload, '\n')

	writeDone := make(chan error, 1)
	go func() {
		_, err := connection.Write(payload[:7])
		if err == nil {
			_, err = connection.Write(payload[7:])
		}
		writeDone <- err
	}()
	_ = readTestFrame[HelloResponse](t, reader)
	decision := readTestFrame[DecisionResponse](t, reader)
	if decision.Decision != "allow" {
		t.Fatalf("decision = %#v", decision)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("fragmented write: %v", err)
	}
	_ = connection.Close()
	<-result
}

func TestPermissionGateProtocolOversizedFrame(t *testing.T) {
	connection, result := startTestBroker(t, &recordingAudit{})
	input := bytes.Repeat([]byte{'x'}, MaxFrameBytes+1)
	writeDone := make(chan struct{})
	go func() {
		_, _ = connection.Write(append(input, '\n'))
		close(writeDone)
	}()
	if err := <-result; !errors.Is(err, ErrProtocol) {
		t.Fatalf("Serve() error = %v, want protocol error", err)
	}
	_ = connection.Close()
	<-writeDone
}

func TestPermissionGateAuditLogPrivateAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate", "audit.jsonl")
	log, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	command := strings.Repeat("é", MaxCommandBytes/2)
	record := newAuditRecord("run", AuthorizeRequest{
		ID: "request", Kind: "bash", Command: command,
	}, []Match{{Label: "test"}}, "allow", "approved")
	if err := log.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit mode = %o, want 600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) > maxAuditRecordBytes || bytes.Contains(contents, []byte(command)) {
		t.Fatalf("audit record was not bounded: %d bytes", len(contents))
	}
	var decoded AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(contents), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.CommandTruncated || len(decoded.CommandPreview) > maxAuditCommandPreview {
		t.Fatalf("bounded preview = %d bytes, truncated=%v", len(decoded.CommandPreview), decoded.CommandTruncated)
	}
}
