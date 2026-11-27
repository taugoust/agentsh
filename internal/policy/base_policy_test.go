package policy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var basePolicyTestVars = map[string]string{
	"HOME":         "/home/u",
	"PROJECT_ROOT": "/work/proj",
	"GIT_ROOT":     "/work/proj",
}

// TestShippedPoliciesLoadAndCompile loads every policy in configs/policies,
// resolving extends, and compiles an engine with and without session
// variables.
func TestShippedPoliciesLoadAndCompile(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(findProjectRoot(t), "configs", "policies", "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			p, err := LoadFromFile(path)
			require.NoError(t, err)
			_, err = NewEngine(p, true, true)
			require.NoError(t, err)
			_, err = NewEngineWithVariables(p, true, true, basePolicyTestVars)
			require.NoError(t, err)
		})
	}
}

// TestBasePolicyIsApproveOnly checks that base.yaml only asks for approval,
// that every rule has a message and a timeout, and that its rule names don't
// clash with extending policies.
func TestBasePolicyIsApproveOnly(t *testing.T) {
	p, err := LoadFromFile(filepath.Join(findProjectRoot(t), "configs", "policies", "base.yaml"))
	require.NoError(t, err)
	require.Empty(t, p.Extends)
	check := func(family, name, decision, message string, timeout time.Duration) {
		t.Helper()
		require.True(
			t,
			strings.HasPrefix(name, "base-"),
			"%s rule %q needs the base- prefix",
			family,
			name,
		)
		require.Equal(t, "approve", decision, "%s rule %q", family, name)
		require.NotEmpty(t, message, "%s rule %q needs a message", family, name)
		require.Positive(t, timeout, "%s rule %q needs a timeout", family, name)
	}
	for _, r := range p.FileRules {
		check("file", r.Name, r.Decision, r.Message, r.Timeout.Duration)
	}
	for _, r := range p.NetworkRules {
		check("network", r.Name, r.Decision, r.Message, r.Timeout.Duration)
	}
	for _, r := range p.CommandRules {
		check("command", r.Name, r.Decision, r.Message, r.Timeout.Duration)
	}
	for _, r := range p.UnixRules {
		check("unix socket", r.Name, r.Decision, r.Message, r.Timeout.Duration)
	}
	require.Empty(t, p.SignalRules)
	require.Empty(t, p.RegistryRules)
	require.Empty(t, p.DnsRedirectRules)
	require.Empty(t, p.ConnectRedirectRules)
}

// TestBasePolicyWinsOverExtendingAllow extends base with a policy that allows
// everything. Each case must end in a base approval or in the child's allow.
func TestBasePolicyWinsOverExtendingAllow(t *testing.T) {
	dir := t.TempDir()
	base, err := os.ReadFile(filepath.Join(findProjectRoot(t), "configs", "policies", "base.yaml"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "base.yaml"), base, 0o644))
	const child = `
version: 1
name: allow-all
extends: base
file_rules:
  - name: allow-all-files
    paths: ["**"]
    operations: ["*"]
    decision: allow
network_rules:
  - name: allow-all-network
    decision: allow
command_rules:
  - name: allow-all-commands
    commands: ["*"]
    decision: allow
unix_socket_rules:
  - name: allow-all-unix
    paths: ["**", "@**"]
    decision: allow
`
	childPath := filepath.Join(dir, "allow-all.yaml")
	require.NoError(t, os.WriteFile(childPath, []byte(child), 0o644))
	p, err := LoadFromFile(childPath)
	require.NoError(t, err)
	e, err := NewEngineWithVariables(p, true, true, basePolicyTestVars)
	require.NoError(t, err)

	check := func(what string, d Decision, wantApprove bool) {
		t.Helper()
		if wantApprove {
			if !strings.HasPrefix(d.Rule, "base-") || d.EffectiveDecision != "approve" {
				t.Errorf("%s = %s by %q; want a base approval", what, d.EffectiveDecision, d.Rule)
			}
		} else if !strings.HasPrefix(d.Rule, "allow-all-") || d.EffectiveDecision != "allow" {
			t.Errorf("%s = %s by %q; want the child's allow", what, d.EffectiveDecision, d.Rule)
		}
	}

	files := []struct {
		path, op string
		approve  bool
	}{
		// Credentials
		{"/home/u/.ssh/id_ed25519", "open", true},
		{"/home/u/.ssh/id_ed25519.pub", "open", false},
		{"/home/u/.ssh/id_rsa", "open", true},
		{"/home/u/.ssh/id_ecdsa_sk", "open", true},
		{"/home/u/.ssh/id_rsa.pub", "open", false},
		{"/home/u/.ssh/id_ed25519_sk.pub", "open", false},
		{"/home/u/.ssh/deploy.pem", "read", true},
		{"/home/u/.ssh/known_hosts", "open", false},
		{"/home/u/.git-credentials", "open", true},
		{"/work/proj/.netrc", "open", true},
		{"/home/u/.aws/credentials", "open", true},
		{"/home/u/.aws", "list", true},
		{"/home/u/.config/gcloud/application_default_credentials.json", "open", true},
		{"/home/u/.kube/config", "open", true},
		{"/home/u/.docker/config.json", "open", true},
		{"/home/u/.gnupg/private-keys-v1.d/ABCD.key", "open", true},
		{"/home/u/.gnupg/pubring.kbx", "write", false},
		{"/proc/self/environ", "open", true},
		{"/proc/1234/task/1235/environ", "open", true},
		{"/proc/1234/mem", "open", true},
		{"/proc/kcore", "open", true},
		{"/proc/self/status", "open", false},
		{"/etc/shadow", "open", true},
		{"/etc/gshadow-", "open", true},
		// Persistence: writes need approval, reads allowed
		{"/home/u/.bashrc", "write", true},
		{"/home/u/.bashrc", "open", false},
		{"/home/u/.profile", "rename", true},
		{"/home/u/.zshrc", "create", true},
		{"/home/u/.config/fish/conf.d/x.fish", "create", true},
		{"/home/u/.config/autostart/x.desktop", "create", true},
		{"/home/u/.config/systemd/user/x.service", "create", true},
		{"/var/spool/cron/crontabs/u", "write", true},
		{"/home/u/.ssh/authorized_keys", "write", true},
		{"/home/u/.ssh/known_hosts", "write", false},
		{"/home/u/.gitconfig", "write", true},
		{"/home/u/.gitconfig", "open", false},
		{"/work/proj/.git/config", "write", true},
		{"/work/proj/.git/config", "rename", true},
		{"/work/proj/.git/config", "open", false},
		{"/work/proj/.git/config.lock", "create", false},
		{"/work/proj/.git", "rename", true},
		{"/work/proj/.git", "mkdir", false},
		{"/work/proj/.git/hooks/pre-commit", "create", true},
		{"/work/proj/.git/hooks/pre-commit.sample", "create", true},
		{"/work/proj/.git/index", "write", false},
		{"/tmp/scratch/.git/hooks/pre-commit.sample", "create", false},
		{"/tmp/scratch/.git/hooks/pre-commit", "rename", true},
		{"/tmp/scratch/.git/config", "rename", false},
		{"/work/proj/.envrc", "write", true},
		{"/work/proj/.envrc", "open", false},
		{"/work/proj/sub/.envrc.local", "create", true},
		{"/home/u/.local/share/direnv/allow/abc123", "create", true},
		{"/home/u/.config", "rename", true},
		{"/home/u/.config", "mkdir", false},
		{"/home/u/.config/nvim/init.lua", "write", false},
		// Ordinary project work
		{"/work/proj/src/main.go", "write", false},
		{"/work/proj/src/main.go", "delete", false},
	}
	for _, c := range files {
		check("CheckFile("+c.path+", "+c.op+")", e.CheckFile(c.path, c.op), c.approve)
	}

	cmds := []struct {
		cmd     string
		args    []string
		approve bool
	}{
		// Privilege escalation and out-of-sandbox execution
		{"sudo", []string{"ls"}, true},
		{"/run/wrappers/bin/sudo", []string{"-i"}, true},
		{"/usr/bin/su", nil, true},
		{"pkexec", []string{"bash"}, true},
		{"nsenter", []string{"-t", "1", "-m"}, true},
		{"bash", []string{"-c", "sudo id"}, true},
		{"systemd-run", []string{"--user", "sh"}, true},
		{"crontab", []string{"-e"}, true},
		{"systemctl", []string{"--user", "enable", "--now", "x.service"}, true},
		{"systemctl", []string{"status", "x.service"}, false},
		{"loginctl", []string{"enable-linger", "u"}, true},
		{"direnv", []string{"allow", "."}, true},
		{"direnv", []string{"export", "json"}, false},
		{"git", []string{"status"}, false},
		{"sg", []string{"run", "-p", "foo"}, false}, // ast-grep
	}
	for _, c := range cmds {
		check(
			"CheckCommand("+c.cmd+" "+strings.Join(c.args, " ")+")",
			e.CheckCommand(c.cmd, c.args),
			c.approve,
		)
	}

	nets := []struct {
		domain, ip string
		port       int
		approve    bool
	}{
		// Cloud metadata
		{"", "169.254.169.254", 80, true},
		{"", "::ffff:169.254.169.254", 80, true},
		{"", "fd00:ec2::254", 80, true},
		{"", "169.254.170.2", 80, true},
		{"", "100.100.100.200", 80, true},
		{"metadata.google.internal", "", 80, true},
		{"", "168.63.129.16", 80, true},
		{"", "168.63.129.16", 53, false},
		{"github.com", "140.82.121.4", 443, false},
		{"", "127.0.0.1", 8080, false},
	}
	for _, c := range nets {
		var ip net.IP
		if c.ip != "" {
			ip = net.ParseIP(c.ip)
		}
		check(
			"CheckNetworkIP("+c.domain+", "+c.ip+")",
			e.CheckNetworkIP(c.domain, ip, c.port),
			c.approve,
		)
	}

	socks := []struct {
		path    string
		approve bool
	}{
		{"/run/user/1000/systemd/private", true},
		{"/run/systemd/private", true},
		{"/run/user/1000/bus", false},
		{"/run/dbus/system_bus_socket", false},
		{"/run/user/1000/gnupg/S.gpg-agent", false},
	}
	for _, c := range socks {
		check("CheckUnixSocket("+c.path+")", e.CheckUnixSocket(c.path, "connect"), c.approve)
	}
}
