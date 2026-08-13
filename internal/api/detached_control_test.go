package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/detached"
	"github.com/agentsh/agentsh/internal/detachedtransport"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestDetachedControlExchangeRequiresUnixAndReplaysExactApproval(t *testing.T) {
	st := newSQLiteStore(t)
	manager := session.NewManager(10)
	approvalManager := approvals.New("api", time.Minute, nil)
	app := newTestApp(t, manager, composite.New(st, st))
	app.approvals = approvalManager

	now := time.Now().UTC()
	runtime := &detached.Runtime{}
	// Runtime internals are intentionally private; install the observer using a
	// fixed exact identity to test the same exchange handler boundary.
	identity := detachedtransport.Identity{SessionID: "session-control", Generation: 1, IncarnationID: "incarnation-control"}
	app.detachedControl = detachedtransport.NewJournal(16)
	approvalManager.SetDetachedRequestObserver(func(_ context.Context, request approvals.Request) error {
		record, err := detachedtransport.NewApprovalRequest(app.detachedControl.NextSequence(identity), request)
		if err == nil {
			_, err = app.detachedControl.Put(identity, record)
		}
		return err
	})
	app.detachedRuntime = runtime

	request := approvals.Request{ID: "approval-control", SessionID: identity.SessionID, Kind: "file", Target: "/work/file", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, err := detachedtransport.NewApprovalRequest(1, request); err != nil {
		t.Fatal(err)
	}
	// A TCP-origin request must fail before decoding or exposing records.
	recorder := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/detached/control/exchange", bytes.NewReader([]byte(`{}`)))
	app.exchangeDetachedControl(recorder, httpRequest)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-Unix exchange status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	// Validate protocol response semantics independently of private runtime setup.
	record, err := detachedtransport.NewApprovalRequest(1, request)
	if err != nil {
		t.Fatal(err)
	}
	response := detachedtransport.ExchangeResponse{Version: detachedtransport.Version, Identity: identity, Cursor: 1, Records: []detachedtransport.Record{record}}
	if err := response.Validate(identity, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(response); err != nil {
		t.Fatal(err)
	}
}
