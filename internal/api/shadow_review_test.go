//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/workspace/shadow"
	"github.com/go-chi/chi/v5"
)

func TestShadowReviewRequiresFreshPreconditionAndQuiescence(t *testing.T) {
	st := newSQLiteStore(t)
	manager := session.NewManager(10)
	app := newTestApp(t, manager, composite.New(st, st))
	realRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(realRoot, "value.txt"), []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sess, err := manager.Create(realRoot, "default")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := shadow.Create(context.Background(), sess.ID, realRoot, shadow.Options{BaseDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	sess.SetShadow(workspace)
	if err := os.WriteFile(filepath.Join(workspace.Work, "value.txt"), []byte("draft is newer\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	activity, err := sess.BeginWorkspaceActivity()
	if err != nil {
		t.Fatal(err)
	}
	blockedReview := httptest.NewRecorder()
	app.Router().ServeHTTP(blockedReview, httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID+"/overlay/diff", nil))
	activity.Release()
	if blockedReview.Code != http.StatusConflict {
		t.Fatalf("review with active writer status=%d body=%s", blockedReview.Code, blockedReview.Body.String())
	}

	diffReq := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/"+sess.ID+"/overlay/diff", nil)
	diffRecorder := httptest.NewRecorder()
	app.Router().ServeHTTP(diffRecorder, diffReq)
	if diffRecorder.Code != http.StatusOK {
		t.Fatalf("diff status=%d body=%s", diffRecorder.Code, diffRecorder.Body.String())
	}
	generation := diffRecorder.Header().Get("X-AgentSH-Review-Generation")
	hash := diffRecorder.Header().Get("X-AgentSH-Review-Hash")
	if generation == "" || hash == "" {
		t.Fatalf("missing review headers: %+v", diffRecorder.Header())
	}

	missing := httptest.NewRecorder()
	missingReq := withSessionID(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/overlay/accept", bytes.NewReader([]byte(`{}`))), sess.ID)
	app.acceptOverlay(missing, missingReq)
	if missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing precondition status=%d body=%s", missing.Code, missing.Body.String())
	}

	activity, err = sess.BeginWorkspaceActivity()
	if err != nil {
		t.Fatal(err)
	}
	busy := httptest.NewRecorder()
	busyReq := withSessionID(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/overlay/accept", bytes.NewReader(reviewBody(t, generation, hash))), sess.ID)
	app.acceptOverlay(busy, busyReq)
	activity.Release()
	if busy.Code != http.StatusConflict {
		t.Fatalf("busy finalization status=%d body=%s", busy.Code, busy.Body.String())
	}

	if err := os.WriteFile(filepath.Join(realRoot, "concurrent.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := httptest.NewRecorder()
	staleReq := withSessionID(httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/overlay/accept", bytes.NewReader(reviewBody(t, generation, hash))), sess.ID)
	app.acceptOverlay(stale, staleReq)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale finalization status=%d body=%s", stale.Code, stale.Body.String())
	}
}

func withSessionID(request *http.Request, sessionID string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", sessionID)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func reviewBody(t *testing.T, generation, hash string) []byte {
	t.Helper()
	value, err := strconv.ParseUint(generation, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(shadowAcceptRequest{ReviewGeneration: value, ReviewHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
