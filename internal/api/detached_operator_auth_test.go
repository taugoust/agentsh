package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/detachedtransport"
	"github.com/agentsh/agentsh/internal/session"
)

func TestDetachedControlOnlyAuthorizationIsRouteAndTransportScoped(t *testing.T) {
	manager := session.NewManager(1)
	_, runtimeState, _ := newDetachedExpiryFixture(t, manager)
	if err := runtimeState.SetControlCredential("control-secret"); err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: &config.Config{}, detachedRuntime: runtimeState}
	app.cfg.Auth.Type = "none"
	app.cfg.Development.DisableAuth = true
	app.cfg.Development.DetachedControlOnly = true
	protected := app.requireRoles("approver")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	unix := MarkUnixSocketRequests(protected)

	request := func(handler http.Handler, method, path, token string) int {
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set(detachedtransport.ControlTokenHeader, token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	for _, authorized := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/sessions/session/overlay/accept"},
		{http.MethodGet, "/api/v1/approvals"},
		{http.MethodPost, "/api/v1/approvals/id"},
	} {
		if got := request(unix, authorized.method, authorized.path, "control-secret"); got != http.StatusNoContent {
			t.Fatalf("authorized request status=%d method=%s path=%s", got, authorized.method, authorized.path)
		}
	}
	for _, test := range []struct {
		handler http.Handler
		method  string
		path    string
		token   string
	}{
		{unix, http.MethodPost, "/api/v1/sessions/session/overlay/accept", "wrong"},
		{protected, http.MethodPost, "/api/v1/sessions/session/overlay/accept", "control-secret"},
		{unix, http.MethodGet, "/api/v1/approvals/id", "control-secret"},
		{unix, http.MethodPost, "/api/v1/approvals", "control-secret"},
		{unix, http.MethodGet, "/api/v1/policies", "control-secret"},
	} {
		if got := request(test.handler, test.method, test.path, test.token); got == http.StatusNoContent {
			t.Fatalf("unauthorized request passed path=%s", test.path)
		}
	}
}
