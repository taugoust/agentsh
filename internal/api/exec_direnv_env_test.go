package api

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

func TestCommandOutputArtifactCapture_DirenvEnvironmentPrecedenceAndProtectedFilter(t *testing.T) {
	s := &session.Session{}
	s.SetRuntimePathsWithProcessHome("runtime-home", "runtime-tmp", "operator-home", "real", nil)
	s.ReplaceDirenvEnvironment(map[string]string{
		"PATH": "dev-shell-path", "DEV_SHELL": "ready", "home": "stolen",
		"Http_Proxy": "stolen", "AGENTSH_NOTIFY_SOCK_FD": "99",
	})
	env, err := buildCommandEnvironment(&config.Config{}, policy.ResolvedEnvPolicy{}, []string{"PATH=host-path", "HOME=host-home"}, s, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		got[strings.ToUpper(key)] = value
	}
	if got["PATH"] != "dev-shell-path" || got["DEV_SHELL"] != "ready" {
		t.Fatalf("direnv values not merged: %#v", got)
	}
	if got["HOME"] != "operator-home" || got["HTTP_PROXY"] == "stolen" {
		t.Fatalf("protected values overridden: %#v", got)
	}
	if _, ok := got["AGENTSH_NOTIFY_SOCK_FD"]; ok {
		t.Fatalf("wrapper control survived: %#v", got)
	}
}
