//go:build linux && cgo

package unix

import (
	"context"
	"testing"
)

type staticFileLookupProbe struct{ called bool }

func (p *staticFileLookupProbe) ProbeFileLookup(context.Context, FileLookupRequest) FileLookupResult {
	p.called = true
	return FileLookupResult{Class: LookupExists, Reason: LookupReasonNone}
}

func TestFileHandlerFileLookupProbeHandoffDoesNotAffectDecisions(t *testing.T) {
	probe := &staticFileLookupProbe{}
	handler := NewFileHandler(nil, nil, nil, true)
	handler.SetFileLookupProbe(probe)
	result, _ := handler.Handle(context.Background(), FileRequest{Path: "/missing", Operation: "open"})
	if result.Action != ActionContinue {
		t.Fatalf("result = %+v", result)
	}
	if probe.called {
		t.Fatal("phase 4 must not integrate lookup results into handler decisions")
	}
	if handler.FileLookupProbe() != probe {
		t.Fatal("probe handoff was not retained")
	}
}
