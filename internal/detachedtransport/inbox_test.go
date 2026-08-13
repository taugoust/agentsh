package detachedtransport

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

func TestResolutionInboxExactReplayAppliesOnce(t *testing.T) {
	identity := Identity{SessionID: "session", Generation: 1, IncarnationID: "incarnation"}
	record, err := NewApprovalResolution(1, "approval", approvals.Resolution{Approved: true, Scope: approvals.ScopeOnce, At: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	inbox := NewResolutionInbox(8)
	var calls atomic.Int32
	resolve := func(Record) bool { calls.Add(1); return true }
	if ack, err := inbox.Apply(identity, []Record{record}, resolve); err != nil || ack != 1 {
		t.Fatalf("first apply ack=%d err=%v", ack, err)
	}
	if ack, err := inbox.Apply(identity, []Record{record}, resolve); err != nil || ack != 1 {
		t.Fatalf("replay ack=%d err=%v", ack, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls=%d, want 1", calls.Load())
	}
}

func TestResolutionInboxConcurrentReplayAppliesOnce(t *testing.T) {
	identity := Identity{SessionID: "session", Generation: 2, IncarnationID: "incarnation"}
	record, err := NewApprovalResolution(1, "approval", approvals.Resolution{Approved: false, Scope: approvals.ScopeOnce, At: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	inbox := NewResolutionInbox(8)
	var calls atomic.Int32
	resolve := func(Record) bool { calls.Add(1); return true }
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := inbox.Apply(identity, []Record{record}, resolve); err != nil {
				t.Errorf("Apply: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("resolver calls=%d, want 1", calls.Load())
	}
}

func TestResolutionInboxRejectsGapAndConflictingReplay(t *testing.T) {
	identity := Identity{SessionID: "session", Generation: 1, IncarnationID: "incarnation"}
	inbox := NewResolutionInbox(8)
	second, _ := NewApprovalResolution(2, "approval", approvals.Resolution{Approved: true, Scope: approvals.ScopeOnce, At: time.Now().UTC()})
	if _, err := inbox.Apply(identity, []Record{second}, func(Record) bool { return true }); err == nil {
		t.Fatal("sequence gap was accepted")
	}
	first, _ := NewApprovalResolution(1, "approval", approvals.Resolution{Approved: true, Scope: approvals.ScopeOnce, At: time.Now().UTC()})
	if _, err := inbox.Apply(identity, []Record{first}, func(Record) bool { return true }); err != nil {
		t.Fatal(err)
	}
	conflict, _ := NewApprovalResolution(1, "approval", approvals.Resolution{Approved: false, Scope: approvals.ScopeOnce, At: first.CreatedAt})
	if _, err := inbox.Apply(identity, []Record{conflict}, func(Record) bool { return true }); err == nil {
		t.Fatal("conflicting replay was accepted")
	}
}

func TestJournalAcknowledgmentCompactsWithoutReusingSequence(t *testing.T) {
	identity := Identity{SessionID: "session", Generation: 1, IncarnationID: "incarnation"}
	journal := NewJournal(2)
	now := time.Now().UTC()
	for _, id := range []string{"one", "two"} {
		if _, err := journal.AppendApproval(identity, approvals.Request{ID: id, SessionID: identity.SessionID, Kind: "file", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := journal.AppendApproval(identity, approvals.Request{ID: "full", SessionID: identity.SessionID, Kind: "file", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err == nil {
		t.Fatal("full unacknowledged journal accepted another record")
	}
	if err := journal.Acknowledge(identity, 2); err != nil {
		t.Fatal(err)
	}
	record, err := journal.AppendApproval(identity, approvals.Request{ID: "three", SessionID: identity.SessionID, Kind: "file", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if record.Sequence != 3 {
		t.Fatalf("sequence=%d, want 3", record.Sequence)
	}
}
