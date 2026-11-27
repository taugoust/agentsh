// internal/mcpinspect/protocol_test.go
package mcpinspect

import (
	"testing"
)

func TestMessageToolsListChanged_String(t *testing.T) {
	got := MessageToolsListChanged.String()
	want := "notifications/tools/list_changed"
	if got != want {
		t.Errorf("MessageToolsListChanged.String() = %q, want %q", got, want)
	}
}
