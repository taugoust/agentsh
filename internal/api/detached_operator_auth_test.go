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

	request := func(handler http.Handler, path, token string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if token != "" {
			req.Header.Set(detachedtransport.ControlTokenHeader, token)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}
	if got := request(unix, "/api/v1/sessions/session/overlay/accept", "control-secret"); got != http.StatusNoContent {
		t.Fatalf("authorized accept status=%d", got)
	}
	for _, test := range []struct {
		handler http.Handler
		path    string
		token   string
	}{
		{unix, "/api/v1/sessions/session/overlay/accept", "wrong"},
		{protected, "/api/v1/sessions/session/overlay/accept", "control-secret"},
		{unix, "/api/v1/approvals/id", "control-secret"},
		{unix, "/api/v1/policies", "control-secret"},
	} {
		if got := request(test.handler, test.path, test.token); got == http.StatusNoContent {
			t.Fatalf("unauthorized request passed path=%s", test.path)
		}
	}
}
