package detachedtransport

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
)

func TestJournalReplaysExactRecordsAndRejectsConflictsAcrossExactIdentity(t *testing.T) {
	identity := Identity{SessionID: "session-one", Generation: 2, IncarnationID: "incarnation-two"}
	request := approvals.Request{ID: "approval-one", SessionID: identity.SessionID, Kind: "file", Target: "/work/a", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	record, err := NewApprovalRequest(1, request)
	if err != nil {
		t.Fatal(err)
	}
	journal := NewJournal(4)
	if inserted, err := journal.Put(identity, record); err != nil || !inserted {
		t.Fatalf("first put inserted=%t err=%v", inserted, err)
	}
	if inserted, err := journal.Put(identity, record); err != nil || inserted {
		t.Fatalf("replay inserted=%t err=%v", inserted, err)
	}
	conflict, err := cloneRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	conflict.Approval.Target = "/work/b"
	if err := conflict.seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Put(identity, conflict); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v", err)
	}
	late, err := NewApprovalRequest(1, approvals.Request{ID: "late", SessionID: identity.SessionID, Kind: "file", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Put(identity, late); err == nil || !strings.Contains(err.Error(), "monotonic") {
		t.Fatalf("late sequence error = %v", err)
	}
	got := journal.Since(identity, 0, 10, KindApprovalRequested)
	if len(got) != 1 || got[0].Digest != record.Digest {
		t.Fatalf("journal replay = %+v", got)
	}
}

func TestExchangeStrictlyValidatesVersionDigestAndOrdering(t *testing.T) {
	identity := Identity{SessionID: "session-one", Generation: 1, IncarnationID: "incarnation-one"}
	first, err := NewApprovalRequest(2, approvals.Request{ID: "a", SessionID: identity.SessionID, Kind: "command", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewApprovalRequest(1, approvals.Request{ID: "b", SessionID: identity.SessionID, Kind: "command", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	request := ExchangeRequest{Version: Version, Identity: identity, Limit: 16, Records: []Record{first, second}}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "ordered") {
		t.Fatalf("ordering error = %v", err)
	}
	first.Digest = "sha256:" + strings.Repeat("0", 64)
	request.Records = []Record{first}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest error = %v", err)
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) == 0 {
		t.Fatalf("marshal request: %v", err)
	}
}
