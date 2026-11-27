// internal/policygen/risky_test.go
package policygen

import "testing"

func TestRiskyDetector_MarkNetworkCapable(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkNetworkCapable("my-custom-tool")

	if !d.IsRisky("my-custom-tool") {
		t.Error("expected my-custom-tool to be risky after marking")
	}
	reason := d.Reason("my-custom-tool")
	if reason != "network-observed" {
		t.Errorf("expected reason 'network-observed', got %q", reason)
	}
}

func TestRiskyDetector_MarkDestructive(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkDestructive("cleanup-script")

	if !d.IsRisky("cleanup-script") {
		t.Error("expected cleanup-script to be risky after marking")
	}
}
