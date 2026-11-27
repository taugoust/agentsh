package approvals

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A server without a terminal (for example under systemd) must deny a
// local_tty approval right away instead of allowing it or waiting for the
// approval timeout.
func TestRequestApproval_LocalTTYWithoutTerminalDeniesPromptly(t *testing.T) {
	m := New("local_tty", time.Minute, nil)
	m.ttyPath = filepath.Join(t.TempDir(), "missing-tty")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	res, err := m.RequestApproval(ctx, Request{
		SessionID: "s-notty",
		Kind:      "command",
		Target:    "sudo",
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RequestApproval error = %v, want a plain denial", err)
	}
	if res.Approved {
		t.Fatal("approval granted without a terminal, want denied")
	}
	if !strings.Contains(res.Reason, "no terminal for local approval prompt") {
		t.Fatalf("reason = %q, want it to name the missing terminal", res.Reason)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("denial took %v, want it well before the approval timeout", elapsed)
	}
}
