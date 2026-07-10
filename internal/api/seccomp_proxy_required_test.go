//go:build linux

package api

import (
	"path/filepath"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)

func TestAppendProxyRequiredUnsupportedTrafficRulesOverridesWeakerRules(t *testing.T) {
	rawType := 3
	cfg := &seccompWrapperConfig{
		BlockedFamilies: []seccompkg.BlockedFamily{{
			Family: 17,
			Name:   "AF_PACKET",
			Action: seccompkg.OnBlockLog,
		}},
		SocketRules: []seccompkg.SocketRule{{
			Name:   "weak-raw-ipv4",
			Family: 2,
			Type:   &rawType,
			Action: seccompkg.OnBlockLog,
		}},
	}

	appendProxyRequiredUnsupportedTrafficRules(cfg)

	if !proxyRequiredRawSocketRulesConfigured(cfg) {
		t.Fatalf("proxy-required raw/packet rules were not configured: families=%+v rules=%+v", cfg.BlockedFamilies, cfg.SocketRules)
	}
	for _, family := range cfg.BlockedFamilies {
		if family.Family == 17 && family.Action != seccompkg.OnBlockErrno {
			t.Fatalf("AF_PACKET action = %q, want errno", family.Action)
		}
	}
	for _, rule := range cfg.SocketRules {
		if rule.Family == 2 && rule.Type != nil && *rule.Type == rawType && rule.Protocol == nil && rule.Action != seccompkg.OnBlockErrno {
			t.Fatalf("IPv4 raw action = %q, want errno", rule.Action)
		}
	}
}

func TestSupportedDelegatedSupervisorCgroup(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "sys", "fs", "cgroup", "user.slice", "agentsh-supervisor-session-123.service")
	if !supportedDelegatedSupervisorCgroup(root) {
		t.Fatal("expected transient delegated supervisor unit to be accepted")
	}
	if !supportedDelegatedSupervisorCgroup(filepath.Join(root, "agentsh.leaf")) {
		t.Fatal("expected fixed supervisor leaf to normalize to its unit root")
	}
	for _, path := range []string{
		filepath.Join(string(filepath.Separator), "sys", "fs", "cgroup", "user.slice", "user@1000.service"),
		filepath.Join(string(filepath.Separator), "sys", "fs", "cgroup", "system.slice", "agentsh.service"),
		"",
	} {
		if supportedDelegatedSupervisorCgroup(path) {
			t.Fatalf("unsupported cgroup root %q was accepted", path)
		}
	}
}
