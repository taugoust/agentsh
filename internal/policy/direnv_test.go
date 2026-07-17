package policy

import (
	"strings"
	"testing"
)

func validDirenvPolicy() DirenvImportPolicy {
	p := DirenvImportPolicy{
		Enabled: true, Allow: []string{"*"}, MaxKeys: 64, MaxValueBytes: 4096,
		MaxBytes: 32768, MaxStdoutBytes: 65536, MaxStderrBytes: 4096,
	}
	p.QueueTimeout.Duration = 1000000000
	p.EvaluationTimeout.Duration = 2000000000
	return p
}

func TestDiscoverProjectOverlays_DirenvImportPolicyValidation(t *testing.T) {
	p := validDirenvPolicy()
	if err := ValidateDirenvImportPolicy(p); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	p.Allow = []string{"["}
	if err := ValidateDirenvImportPolicy(p); err == nil {
		t.Fatal("expected malformed glob rejection")
	}
	p = validDirenvPolicy()
	p.MaxKeys = 0
	if err := ValidateDirenvImportPolicy(p); err == nil {
		t.Fatal("expected non-positive bound rejection")
	}
}

func TestDiscoverProjectOverlays_DirenvImmutableDenies(t *testing.T) {
	for _, name := range []string{
		"PATH", "HOME", "home", "AGENTSH_SESSION", "Pi_AgentSH_URL", "PI_AUTO_MODE",
		"LD_PRELOAD", "dyld_insert_libraries", "BASH_ENV", "NODE_OPTIONS", "PYTHONPATH",
		"PROJECT_TOKEN", "aws_secret_access_key", "HTTP_PROXY", "ssh_auth_sock",
	} {
		got := DirenvImportImmutableDenied(name)
		want := !strings.EqualFold(name, "PATH")
		if got != want {
			t.Errorf("DirenvImportImmutableDenied(%q) = %v, want %v", name, got, want)
		}
	}
}
