package approvals

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type stubEmitter struct {
	mu     sync.Mutex
	events []types.Event
}

func (s *stubEmitter) AppendEvent(ctx context.Context, ev types.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}
func (s *stubEmitter) Publish(ev types.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func TestRequestApprovalContextCancel(t *testing.T) {
	em := &stubEmitter{}
	mgr := New("remote", 2*time.Second, em)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := mgr.RequestApproval(ctx, Request{Kind: "network", Target: "example.com"})
	if err == nil || res.Approved || res.Reason != "context canceled" {
		t.Fatalf("expected canceled resolution, got res=%+v err=%v", res, err)
	}
	if len(em.events) != 0 {
		t.Fatalf("pre-canceled request emitted events: %+v", em.events)
	}
	if pending := mgr.ListPending(); len(pending) != 0 {
		t.Fatalf("pre-canceled request became pending: %+v", pending)
	}
}

func TestRequestApprovalTimeout(t *testing.T) {
	em := &stubEmitter{}
	mgr := New("remote", 5*time.Millisecond, em)

	ctx := context.Background()
	res, err := mgr.RequestApproval(ctx, Request{Kind: "command", Target: "ls"})
	if err == nil || res.Approved {
		t.Fatalf("expected timeout/deny, got res=%+v err=%v", res, err)
	}
	if res.Reason != "approval timeout" {
		t.Fatalf("unexpected reason %q", res.Reason)
	}
}
