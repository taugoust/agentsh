package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type subagentStreamRecorder struct {
	mu         sync.Mutex
	header     http.Header
	body       bytes.Buffer
	flushes    int
	writeErr   error
	statusCode int
}

func (r *subagentStreamRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *subagentStreamRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *subagentStreamRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil {
		return 0, r.writeErr
	}
	return r.body.Write(p)
}

func (r *subagentStreamRecorder) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
}

func (r *subagentStreamRecorder) lines() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(r.body.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			panic(err)
		}
		events = append(events, event)
	}
	return events
}

func TestSubagentStreamerEmitsExactlyOneDone(t *testing.T) {
	recorder := &subagentStreamRecorder{}
	stream := newSubagentStreamer(recorder, recorder)
	if err := stream.Emit("stdout", map[string]any{"data": "partial"}); err != nil {
		t.Fatalf("emit progress: %v", err)
	}

	var wg sync.WaitGroup
	var successes int
	var successesMu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			err := stream.Done(map[string]any{"ok": true, "result": index})
			if err == nil {
				successesMu.Lock()
				successes++
				successesMu.Unlock()
			} else if !errors.Is(err, errSubagentStreamTerminal) {
				t.Errorf("Done error = %v", err)
			}
		}(i)
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful Done calls = %d, want 1", successes)
	}
	if err := stream.Emit("stdout", map[string]any{"data": "after"}); !errors.Is(err, errSubagentStreamTerminal) {
		t.Fatalf("post-terminal Emit error = %v, want terminal error", err)
	}

	events := recorder.lines()
	if len(events) != 2 || events[0]["event"] != "stdout" || events[1]["event"] != "done" {
		t.Fatalf("events = %#v", events)
	}
}

func TestSubagentStreamerSurfacesWriteFailure(t *testing.T) {
	writeErr := errors.New("injected write failure")
	recorder := &subagentStreamRecorder{writeErr: writeErr}
	stream := newSubagentStreamer(recorder, recorder)
	if err := stream.Emit("stdout", map[string]any{"data": "partial"}); !errors.Is(err, writeErr) {
		t.Fatalf("Emit error = %v, want injected failure", err)
	}
	if !errors.Is(stream.Err(), writeErr) {
		t.Fatalf("stream error = %v, want injected failure", stream.Err())
	}
	if err := stream.Done(map[string]any{"ok": false}); !errors.Is(err, writeErr) {
		t.Fatalf("Done error = %v, want retained write failure", err)
	}
}
