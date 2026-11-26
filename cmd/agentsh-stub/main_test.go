package main

import "testing"

func TestRunNeitherEnvSet(t *testing.T) {
	t.Setenv("AGENTSH_STUB_FD", "")

	code := run()
	if code != 126 {
		t.Errorf("expected exit code 126, got %d", code)
	}
}

func TestRunInvalidFD(t *testing.T) {
	t.Setenv("AGENTSH_STUB_FD", "not-a-number")

	code := run()
	if code != 126 {
		t.Errorf("expected exit code 126, got %d", code)
	}
}
