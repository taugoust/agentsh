package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func newAPIOutputArtifactSession(t *testing.T, maxBytes int64) *session.Session {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := session.NewManager(1).Create(workspace, "default")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	runtimeHome := filepath.Join(runtimeRoot, "home")
	runtimeTmp := filepath.Join(runtimeRoot, "tmp")
	for _, dir := range []string{runtimeHome, runtimeTmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRuntimePaths(runtimeHome, runtimeTmp, nil)
	if err := s.ConfigureOutputArtifacts(maxBytes); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCommandOutputArtifactCapture_LazyCompleteCombinedOutput(t *testing.T) {
	s := newAPIOutputArtifactSession(t, 1024)
	capture := newCommandOutputArtifactCapture(s, "command", &types.OutputArtifactRequest{
		PersistOverBytes: 5,
		PersistOverLines: 100,
	})
	if err := capture.Append([]byte("out")); err != nil {
		t.Fatal(err)
	}
	if got := capture.Finish(); got != nil {
		t.Fatalf("short output unexpectedly produced artifact: %+v", got)
	}

	capture = newCommandOutputArtifactCapture(s, "command", &types.OutputArtifactRequest{
		PersistOverBytes: 5,
		PersistOverLines: 100,
	})
	for _, chunk := range []string{"out", "err", "tail"} {
		if err := capture.Append([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	result := capture.Finish()
	if result == nil || result.Path == "" || !result.Complete {
		t.Fatalf("artifact result = %+v", result)
	}
	if result.Bytes != 10 || result.TotalBytes != 10 {
		t.Fatalf("artifact byte metadata = %+v, want 10", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "outerrtail" {
		t.Fatalf("artifact content = %q, want combined write order", got)
	}
}

func TestCommandOutputArtifactCapture_LineThreshold(t *testing.T) {
	s := newAPIOutputArtifactSession(t, 1024)
	capture := newCommandOutputArtifactCapture(s, "lines", &types.OutputArtifactRequest{
		PersistOverBytes: 1024,
		PersistOverLines: 2,
	})
	_ = capture.Append([]byte("one\ntwo\n"))
	if got := capture.Finish(); got != nil {
		t.Fatalf("exact line threshold unexpectedly produced artifact: %+v", got)
	}

	capture = newCommandOutputArtifactCapture(s, "lines", &types.OutputArtifactRequest{
		PersistOverBytes: 1024,
		PersistOverLines: 2,
	})
	_ = capture.Append([]byte("one\ntwo\nthree"))
	result := capture.Finish()
	if result == nil || !result.Complete {
		t.Fatalf("line overflow artifact = %+v", result)
	}
}

func TestCommandOutputArtifactCapture_ConfiguredCapIsHonest(t *testing.T) {
	s := newAPIOutputArtifactSession(t, 8)
	capture := newCommandOutputArtifactCapture(s, "bounded", &types.OutputArtifactRequest{
		PersistOverBytes: 3,
	})
	_ = capture.Append([]byte("12345"))
	_ = capture.Append([]byte("67890"))
	result := capture.Finish()
	if result == nil || result.Path == "" {
		t.Fatalf("artifact result = %+v", result)
	}
	if result.Bytes != 8 || result.TotalBytes != 10 || result.Complete {
		t.Fatalf("bounded artifact metadata = %+v", result)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "12345678" {
		t.Fatalf("bounded artifact content = %q", data)
	}
}

func TestCommandOutputArtifactCapture_WriteFailureDoesNotPanic(t *testing.T) {
	s := &session.Session{}
	if err := s.ConfigureOutputArtifacts(16); err != nil {
		t.Fatal(err)
	}
	capture := newCommandOutputArtifactCapture(s, "missing-runtime", &types.OutputArtifactRequest{PersistOverBytes: 1})
	_ = capture.Append([]byte("overflow"))
	result := capture.Finish()
	if result == nil || result.ErrorMessage == "" || result.Complete || result.Path != "" {
		t.Fatalf("failed artifact result = %+v", result)
	}
	if result.TotalBytes != int64(len("overflow")) {
		t.Fatalf("failed artifact total = %d", result.TotalBytes)
	}
}

func TestValidateOutputArtifactRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *types.OutputArtifactRequest
		ok   bool
	}{
		{name: "disabled", req: nil, ok: true},
		{name: "valid", req: &types.OutputArtifactRequest{PersistOverBytes: 50 * 1024, PersistOverLines: 200}, ok: true},
		{name: "missing byte threshold", req: &types.OutputArtifactRequest{PersistOverLines: 200}},
		{name: "negative lines", req: &types.OutputArtifactRequest{PersistOverBytes: 1, PersistOverLines: -1}},
		{name: "oversized threshold", req: &types.OutputArtifactRequest{PersistOverBytes: maxOutputArtifactPresentationThreshold + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOutputArtifactRequest(tc.req)
			if tc.ok && err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("validation unexpectedly succeeded")
			}
		})
	}
}

func TestPersistSubagentFinalArtifact_TrustAndSanitization(t *testing.T) {
	s := newAPIOutputArtifactSession(t, 4096)
	app := &App{}
	result := subagentResult{
		Label:           "child",
		Final:           strings.Repeat("visible ", 16) + "Bearer abc.def api_key=secret-value",
		ModelStopReason: "stop",
		ProtocolSettled: true,
		Terminal:        completedSubagentTerminal(0, subagentTerminationNatural),
	}
	app.persistSubagentFinalArtifact(s, &result, "pi-json", 16)
	if result.FullResultPath == "" || !result.FinalTruncated || result.ArtifactComplete == nil || !*result.ArtifactComplete {
		t.Fatalf("subagent artifact metadata = %+v", result)
	}
	data, err := os.ReadFile(result.FullResultPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "abc.def") || strings.Contains(text, "secret-value") {
		t.Fatalf("artifact retained credential material: %q", text)
	}
	if !strings.Contains(text, "Bearer [redacted]") || !strings.Contains(text, "api_key=[redacted]") {
		t.Fatalf("artifact redaction missing: %q", text)
	}

	for _, untrusted := range []subagentResult{
		{Final: strings.Repeat("x", 100), ModelStopReason: "toolUse", ProtocolSettled: true, Terminal: completedSubagentTerminal(0, subagentTerminationNatural)},
		{Final: strings.Repeat("x", 100), ModelStopReason: "stop", ProtocolSettled: false, Terminal: completedSubagentTerminal(0, subagentTerminationNatural)},
		{Final: strings.Repeat("x", 100), ModelStopReason: "stop", ProtocolSettled: true, Terminal: failedSubagentTerminal(subagentFailureModel, 1, "", subagentTerminationNatural, false, "failed")},
	} {
		app.persistSubagentFinalArtifact(s, &untrusted, "pi-json", 16)
		if untrusted.FullResultPath != "" || untrusted.FinalTruncated {
			t.Fatalf("untrusted result received artifact: %+v", untrusted)
		}
	}
}
