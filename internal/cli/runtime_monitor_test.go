package cli

import "testing"

func TestRuntimeMonitorCommandRemainsHiddenAndStateDirOnly(t *testing.T) {
	cmd := newRuntimeMonitorCmd()
	if !cmd.Hidden {
		t.Fatal("runtime monitor command must remain hidden")
	}
	if cmd.Flags().Lookup("state-dir") == nil {
		t.Fatal("runtime monitor omitted its protected state-directory input")
	}
	for _, forbidden := range []string{"runner", "workspace", "share", "device", "qemu-arg", "environment"} {
		if cmd.Flags().Lookup(forbidden) != nil {
			t.Fatalf("runtime monitor exposed caller-controlled %s selection", forbidden)
		}
	}
}
