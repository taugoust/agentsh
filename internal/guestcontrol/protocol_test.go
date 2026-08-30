package guestcontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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
		SupervisorToken:    strings.Repeat("4", 64),
		Profile:            "pi-linux-qemu-v1",
		ProfileDigest:      "sha256:" + strings.Repeat("3", 64),
		Policy:             "pi-autonomous",
		Workspace:          workspace,
		VSockCID:           41001,
		VSockPort:          18081,
		SupervisorPort:     18082,
		ExpectedGeneration: 1,
		VolumeID:           "22222222-2222-4222-8222-222222222222",
	}
}

func testHandshake(manifest Manifest) Handshake {
	capabilities := []string{"exec_probe", "shutdown", "supervisor_proxy"}
	if manifest.ProtocolVersion == ProtocolVersionV3 || manifest.ProtocolVersion == ProtocolVersionV4 {
		capabilities = append(capabilities, "artifact_import", "artifact_export")
	}
	if manifest.ProtocolVersion == ProtocolVersionV4 {
		capabilities = append(capabilities, "host_egress_proxy")
	}
	return Handshake{
		ProtocolVersion: manifest.ProtocolVersion,
		SessionID:       manifest.SessionID,
		Generation:      manifest.ExpectedGeneration,
		IncarnationID:   "incarnation-test",
		LaunchNonce:     manifest.LaunchNonce,
		GuestBootID:     "boot-test",
		Profile:         manifest.Profile,
		ProfileDigest:   manifest.ProfileDigest,
		AgentSHVersion:  "test",
		EventToken:      strings.Repeat("7", 64),
		Policy:          manifest.Policy,
		VSockCID:        manifest.VSockCID,
		VSockPort:       manifest.VSockPort,
		SupervisorPort:  manifest.SupervisorPort,
		Capabilities:    capabilities,
		VolumeID:        manifest.VolumeID,
		EgressPort:      manifest.EgressPort,
		EgressReady:     manifest.ProtocolVersion == ProtocolVersionV4,
	}
}

func TestProtocolV4BindsUniqueEgressEndpointAndOlderVersionsRejectField(t *testing.T) {
	workspace := t.TempDir()
	manifest := testManifest(workspace)
	manifest.ProtocolVersion = ProtocolVersionV4
	manifest.EgressPort = 41001
	manifest.EgressToken = strings.Repeat("5", 64)
	if err := manifest.Validate(workspace, manifest.Profile, manifest.ProfileDigest, []string{manifest.Policy}); err != nil {
		t.Fatalf("protocol v4 manifest: %v", err)
	}
	handshake := testHandshake(manifest)
	if err := handshake.Validate(manifest); err != nil {
		t.Fatalf("protocol v4 handshake: %v", err)
	}
	claimsDirectNetwork := handshake
	claimsDirectNetwork.NetworkReady = true
	if err := claimsDirectNetwork.Validate(manifest); err == nil {
		t.Fatal("protocol v4 readiness claimed direct-network enforcement")
	}
	missingEgressReadiness := handshake
	missingEgressReadiness.EgressReady = false
	if err := missingEgressReadiness.Validate(manifest); err == nil {
		t.Fatal("protocol v4 handshake omitted explicit-proxy readiness")
	}

	for name, mutate := range map[string]func(*Manifest){
		"missing port":     func(m *Manifest) { m.EgressPort = 0 },
		"missing token":    func(m *Manifest) { m.EgressToken = "" },
		"token reuse":      func(m *Manifest) { m.EgressToken = m.ControlToken },
		"control reuse":    func(m *Manifest) { m.EgressPort = m.VSockPort },
		"supervisor reuse": func(m *Manifest) { m.EgressPort = m.SupervisorPort },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := manifest
			mutate(&invalid)
			if err := invalid.Validate(workspace, invalid.Profile, invalid.ProfileDigest, []string{invalid.Policy}); err == nil {
				t.Fatal("invalid protocol-v4 egress endpoint was accepted")
			}
		})
	}

	legacy := testManifest(workspace)
	for _, field := range []string{"egress_port", "egress_token"} {
		legacyData, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		legacyData[len(legacyData)-1] = ','
		legacyData = append(legacyData, []byte(fmt.Sprintf(`%q:null}`, field))...)
		var decoded Manifest
		if err := json.Unmarshal(legacyData, &decoded); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("protocol-v3 %s error = %v", field, err)
		}
	}

	legacyHandshake := testHandshake(legacy)
	for _, field := range []string{"egress_port", "egress_ready"} {
		handshakeData, err := json.Marshal(legacyHandshake)
		if err != nil {
			t.Fatal(err)
		}
		handshakeData[len(handshakeData)-1] = ','
		handshakeData = append(handshakeData, []byte(fmt.Sprintf(`%q:null}`, field))...)
		var decodedHandshake Handshake
		if err := json.Unmarshal(handshakeData, &decodedHandshake); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("protocol-v3 handshake %s error = %v", field, err)
		}
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

func TestManifestVersionsBindVolumeIdentity(t *testing.T) {
	workspace := t.TempDir()
	current := testManifest(workspace)
	if err := current.Validate(workspace, current.Profile, current.ProfileDigest, []string{current.Policy}); err != nil {
		t.Fatalf("protocol v3 manifest: %v", err)
	}
	missingVolume := current
	missingVolume.VolumeID = ""
	if err := missingVolume.Validate(workspace, current.Profile, current.ProfileDigest, []string{current.Policy}); err == nil {
		t.Fatal("protocol v3 manifest without a volume identity was accepted")
	}
	noncanonicalVolume := current
	noncanonicalVolume.VolumeID = strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err := noncanonicalVolume.Validate(workspace, current.Profile, current.ProfileDigest, []string{current.Policy}); err == nil {
		t.Fatal("protocol v3 manifest with a noncanonical volume identity was accepted")
	}

	legacy := current
	legacy.ProtocolVersion = ProtocolVersionV2
	legacy.VolumeID = ""
	if err := legacy.Validate(workspace, legacy.Profile, legacy.ProfileDigest, []string{legacy.Policy}); err != nil {
		t.Fatalf("retained protocol v2 manifest: %v", err)
	}
	legacy.VolumeID = current.VolumeID
	if err := legacy.Validate(workspace, legacy.Profile, legacy.ProfileDigest, []string{legacy.Policy}); err == nil {
		t.Fatal("legacy protocol v2 manifest carrying a volume identity was accepted")
	}
}

func TestHandshakeBindsManifestProtocolAndVolume(t *testing.T) {
	manifest := testManifest(t.TempDir())
	handshake := testHandshake(manifest)
	if err := handshake.Validate(manifest); err != nil {
		t.Fatal(err)
	}
	wrongVolume := handshake
	wrongVolume.VolumeID = "33333333-3333-4333-8333-333333333333"
	if err := wrongVolume.Validate(manifest); err == nil {
		t.Fatal("handshake for a different volume was accepted")
	}
	wrongProtocol := handshake
	wrongProtocol.ProtocolVersion = ProtocolVersionV2
	if err := wrongProtocol.Validate(manifest); err == nil {
		t.Fatal("handshake for a different protocol was accepted")
	}

	legacyManifest := manifest
	legacyManifest.ProtocolVersion = ProtocolVersionV2
	legacyManifest.VolumeID = ""
	legacyHandshake := testHandshake(legacyManifest)
	if err := legacyHandshake.Validate(legacyManifest); err != nil {
		t.Fatalf("retained protocol v2 handshake: %v", err)
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
		{"supervisor token", func(m *Manifest) { m.SupervisorToken = m.ControlToken }},
		{"profile digest", func(m *Manifest) { m.ProfileDigest = "sha256:bad" }},
		{"cid", func(m *Manifest) { m.VSockCID = 2 }},
		{"port", func(m *Manifest) { m.VSockPort = 22 }},
		{"supervisor port", func(m *Manifest) { m.SupervisorPort = m.VSockPort }},
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

func TestRetainedProtocolV2OperationsUseManifestVersion(t *testing.T) {
	manifest := testManifest(t.TempDir())
	manifest.ProtocolVersion = ProtocolVersionV2
	manifest.VolumeID = ""
	handler := &fakeHandler{handshake: testHandshake(manifest)}
	request := Request{
		ProtocolVersion: manifest.ProtocolVersion,
		Type:            "hello",
		LaunchNonce:     manifest.LaunchNonce,
		ControlToken:    manifest.ControlToken,
		RequestID:       "legacy-hello",
	}
	response, shutdown := exchange(t, manifest, handler, request)
	if shutdown || !response.OK || response.ProtocolVersion != ProtocolVersionV2 || response.Handshake == nil || response.Handshake.ProtocolVersion != ProtocolVersionV2 || response.Handshake.VolumeID != "" {
		t.Fatalf("legacy response = %+v shutdown=%t", response, shutdown)
	}

	wrongVersion := request
	wrongVersion.ProtocolVersion = ProtocolVersionV3
	wrongVersion.RequestID = "wrong-version"
	response, shutdown = exchange(t, manifest, handler, wrongVersion)
	if shutdown || response.OK || response.ProtocolVersion != ProtocolVersionV2 || response.Error != "authentication failed" {
		t.Fatalf("legacy wrong-version response = %+v shutdown=%t", response, shutdown)
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
