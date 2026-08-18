package guestcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testManifest(workspace string) Manifest {
	return Manifest{
		ProtocolVersion:    ProtocolVersion,
		SessionID:          "session-11111111-1111-4111-8111-111111111111",
		LaunchNonce:        strings.Repeat("1", 64),
		ControlToken:       strings.Repeat("2", 64),
		Profile:            "pi-linux-qemu-v1",
		ProfileDigest:      "sha256:" + strings.Repeat("3", 64),
		Policy:             "pi-autonomous",
		Workspace:          workspace,
		VSockCID:           41001,
		VSockPort:          18081,
		ExpectedGeneration: 1,
	}
}

func testHandshake(manifest Manifest) Handshake {
	return Handshake{
		ProtocolVersion: ProtocolVersion,
		SessionID:       manifest.SessionID,
		Generation:      manifest.ExpectedGeneration,
		IncarnationID:   "incarnation-test",
		LaunchNonce:     manifest.LaunchNonce,
		GuestBootID:     "boot-test",
		Profile:         manifest.Profile,
		ProfileDigest:   manifest.ProfileDigest,
		AgentSHVersion:  "test",
		Policy:          manifest.Policy,
		VSockCID:        manifest.VSockCID,
		VSockPort:       manifest.VSockPort,
		Capabilities:    []string{"exec_probe", "shutdown"},
	}
}

func TestReadManifestStrictAndProtected(t *testing.T) {
	workspace := t.TempDir()
	manifest := testManifest(workspace)
	path := filepath.Join(t.TempDir(), "request.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadManifest(path, workspace, manifest.Profile, manifest.ProfileDigest, []string{"pi-autonomous"})
	if err != nil {
		t.Fatal(err)
	}
	if got != manifest {
		t.Fatalf("manifest = %+v, want %+v", got, manifest)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path, workspace, manifest.Profile, manifest.ProfileDigest, []string{"pi-autonomous"}); err == nil {
		t.Fatal("group-readable guest manifest was accepted")
	}
}

func TestManifestRejectsUntrustedSelections(t *testing.T) {
	workspace := t.TempDir()
	base := testManifest(workspace)
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"workspace", func(m *Manifest) { m.Workspace = filepath.Join(workspace, "other") }},
		{"policy", func(m *Manifest) { m.Policy = "untrusted" }},
		{"nonce", func(m *Manifest) { m.LaunchNonce = "short" }},
		{"token", func(m *Manifest) { m.ControlToken = "short" }},
		{"profile digest", func(m *Manifest) { m.ProfileDigest = "sha256:bad" }},
		{"cid", func(m *Manifest) { m.VSockCID = 2 }},
		{"port", func(m *Manifest) { m.VSockPort = 22 }},
		{"generation", func(m *Manifest) { m.ExpectedGeneration = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := base
			test.mutate(&manifest)
			if err := manifest.Validate(workspace, base.Profile, base.ProfileDigest, []string{"pi-autonomous"}); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

type fakeHandler struct {
	handshake Handshake
	mu        sync.Mutex
	requests  map[string]struct{}
	execs     int
	shutdowns int
}

func (h *fakeHandler) Handshake() Handshake { return h.handshake }
func (h *fakeHandler) ClaimRequest(requestID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.requests == nil {
		h.requests = make(map[string]struct{})
	}
	if _, exists := h.requests[requestID]; exists {
		return false
	}
	h.requests[requestID] = struct{}{}
	return true
}
func (h *fakeHandler) ExecProbe(context.Context) (ExecProbeResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.execs++
	return ExecProbeResult{ExitCode: 0, Stdout: "probe\n"}, nil
}
func (h *fakeHandler) Shutdown(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shutdowns++
	return nil
}

func exchange(t *testing.T, manifest Manifest, handler Handler, request Request) (Response, bool) {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct {
		shutdown bool
		err      error
	}, 1)
	go func() {
		shutdown, err := handleConnection(context.Background(), server, manifest, handler)
		_ = server.Close()
		done <- struct {
			shutdown bool
			err      error
		}{shutdown, err}
	}()
	if err := json.NewEncoder(client).Encode(request); err != nil {
		t.Fatal(err)
	}
	var response Response
	decoder := json.NewDecoder(bufio.NewReader(client))
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	return response, result.shutdown
}

func TestAuthenticatedProtocolOperations(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handler := &fakeHandler{handshake: testHandshake(manifest)}
	base := Request{ProtocolVersion: ProtocolVersion, LaunchNonce: manifest.LaunchNonce, ControlToken: manifest.ControlToken}

	hello := base
	hello.Type = "hello"
	hello.RequestID = "hello-1"
	response, shutdown := exchange(t, manifest, handler, hello)
	if shutdown || !response.OK || response.Handshake == nil || response.Handshake.SessionID != manifest.SessionID {
		t.Fatalf("hello response = %+v shutdown=%t", response, shutdown)
	}

	probe := base
	probe.Type = "exec_probe"
	probe.RequestID = "probe-1"
	response, shutdown = exchange(t, manifest, handler, probe)
	if shutdown || !response.OK || response.ExecProbe == nil || response.ExecProbe.Stdout != "probe\n" {
		t.Fatalf("probe response = %+v shutdown=%t", response, shutdown)
	}

	stop := base
	stop.Type = "shutdown"
	stop.RequestID = "stop-1"
	response, shutdown = exchange(t, manifest, handler, stop)
	if !shutdown || !response.OK {
		t.Fatalf("shutdown response = %+v shutdown=%t", response, shutdown)
	}
	if handler.execs != 1 || handler.shutdowns != 1 {
		t.Fatalf("handler calls exec=%d shutdown=%d", handler.execs, handler.shutdowns)
	}
}

func TestProtocolRejectsReplayWithoutDispatch(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handler := &fakeHandler{handshake: testHandshake(manifest)}
	request := Request{
		ProtocolVersion: ProtocolVersion,
		Type:            "exec_probe",
		LaunchNonce:     manifest.LaunchNonce,
		ControlToken:    manifest.ControlToken,
		RequestID:       "probe-replayed",
	}
	first, _ := exchange(t, manifest, handler, request)
	second, shutdown := exchange(t, manifest, handler, request)
	if !first.OK || shutdown || second.OK || second.Error != "duplicate request identity" || handler.execs != 1 {
		t.Fatalf("replay responses first=%+v second=%+v shutdown=%t execs=%d", first, second, shutdown, handler.execs)
	}
}

func TestProtocolRejectsWrongCredentialWithoutDispatch(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handler := &fakeHandler{handshake: testHandshake(manifest)}
	request := Request{
		ProtocolVersion: ProtocolVersion,
		Type:            "exec_probe",
		LaunchNonce:     manifest.LaunchNonce,
		ControlToken:    strings.Repeat("9", 64),
		RequestID:       "probe-unauthenticated",
	}
	response, shutdown := exchange(t, manifest, handler, request)
	if shutdown || response.OK || response.Error != "authentication failed" || handler.execs != 0 {
		t.Fatalf("unauthenticated response = %+v shutdown=%t execs=%d", response, shutdown, handler.execs)
	}
}
