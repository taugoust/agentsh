package config

import (
	"testing"
)

func TestGetSystemMounts(t *testing.T) {
	mounts := GetSystemMounts()

	if len(mounts) == 0 {
		t.Error("expected at least some system mounts")
	}

	// All mounts should have the system-readonly policy
	for _, m := range mounts {
		if m.Policy != "system-readonly" {
			t.Errorf("mount %q has policy %q, want system-readonly", m.Path, m.Policy)
		}
	}

	found := false
	for _, m := range mounts {
		if m.Path == "/usr" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected /usr in system mounts")
	}
}
