//go:build !windows

package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/detachedtransport"
)

func TestExchangeDetachedControlAuthenticatesAndValidatesIdentity(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	identity := detachedtransport.Identity{SessionID: "session", Generation: 1, IncarnationID: "incarnation"}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(detachedtransport.ControlTokenHeader); got != "secret" {
			t.Errorf("token=%q", got)
		}
		var request detachedtransport.ExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode: %v", err)
		}
		if request.Credential != "secret" || request.Identity != identity {
			t.Errorf("request=%+v", request)
		}
		_ = json.NewEncoder(w).Encode(detachedtransport.ExchangeResponse{Version: detachedtransport.Version, Identity: identity})
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	defer os.Remove(socket)

	response, err := ExchangeDetachedControl(context.Background(), socket, "secret", 0, detachedtransport.ExchangeRequest{Version: detachedtransport.Version, Identity: identity, Limit: 8}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if response.Identity != identity {
		t.Fatalf("identity=%+v", response.Identity)
	}
}

func TestExchangeDetachedControlRejectsRelativeSocket(t *testing.T) {
	identity := detachedtransport.Identity{SessionID: "session", Generation: 1, IncarnationID: "incarnation"}
	_, err := ExchangeDetachedControl(context.Background(), "relative.sock", "secret", 0, detachedtransport.ExchangeRequest{Version: detachedtransport.Version, Identity: identity}, time.Second)
	if err == nil {
		t.Fatal("relative socket was accepted")
	}
}
