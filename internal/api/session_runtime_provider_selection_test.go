package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCreateSessionRejectsCallerRuntimeSelection(t *testing.T) {
	st := newSQLiteStore(t)
	app := newTestApp(t, session.NewManager(10), composite.New(st, st))
	handler := app.Router()
	workspace := filepath.ToSlash(t.TempDir())

	for _, field := range []string{"runtime", "runtime_profile", "runtime_provider", "runtime_options"} {
		t.Run(field, func(t *testing.T) {
			value := `"project-selected"`
			if field == "runtime" || field == "runtime_options" {
				value = `{"runner":"/tmp/project-selected"}`
			}
			body := fmt.Sprintf(`{"workspace":%q,%q:%s}`, workspace, field, value)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "runtime selection is operator-owned") {
				t.Fatalf("runtime selection response = %d %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestGRPCCreateSessionRejectsCallerRuntimeSelection(t *testing.T) {
	app := &App{}
	for _, field := range []string{"runtime", "runtime_profile", "runtime_provider", "runtime_options"} {
		t.Run(field, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{%q:"project-selected"}`, field))
			_, err := app.grpcCreateSession(context.Background(), body)
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "runtime selection is operator-owned") {
				t.Fatalf("gRPC runtime selection error = %v", err)
			}
		})
	}
}
