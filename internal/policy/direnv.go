package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/gobwas/glob"
)

// ResolvedDirenvImportPolicy is the validated server-side direnv import policy.
type ResolvedDirenvImportPolicy struct {
	Enabled           bool
	Allow             []string
	Deny              []string
	MaxKeys           int
	MaxValueBytes     int
	MaxBytes          int
	MaxStdoutBytes    int
	MaxStderrBytes    int
	QueueTimeout      time.Duration
	EvaluationTimeout time.Duration
}

func ValidateDirenvImportPolicy(p DirenvImportPolicy) error {
	for kind, patterns := range map[string][]string{"allow": p.Allow, "deny": p.Deny} {
		for _, pattern := range patterns {
			if strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("%s pattern must not be empty", kind)
			}
			if _, err := glob.Compile(strings.ToUpper(pattern)); err != nil {
				return fmt.Errorf("invalid %s pattern %q: %w", kind, pattern, err)
			}
		}
	}
	if !p.Enabled {
		return nil
	}
	if len(p.Allow) == 0 {
		return fmt.Errorf("allow must contain at least one pattern when enabled")
	}
	bounds := map[string]int{
		"max_keys": p.MaxKeys, "max_value_bytes": p.MaxValueBytes,
		"max_bytes": p.MaxBytes, "max_stdout_bytes": p.MaxStdoutBytes,
		"max_stderr_bytes": p.MaxStderrBytes,
	}
	for name, value := range bounds {
		if value <= 0 {
			return fmt.Errorf("%s must be positive when enabled", name)
		}
	}
	if p.QueueTimeout.Duration <= 0 {
		return fmt.Errorf("queue_timeout must be positive when enabled")
	}
	if p.EvaluationTimeout.Duration <= 0 {
		return fmt.Errorf("evaluation_timeout must be positive when enabled")
	}
	return nil
}

func (e *Engine) DirenvImportPolicy() ResolvedDirenvImportPolicy {
	if e == nil || e.policy == nil {
		return ResolvedDirenvImportPolicy{}
	}
	p := e.policy.Direnv
	return ResolvedDirenvImportPolicy{
		Enabled: p.Enabled, Allow: append([]string(nil), p.Allow...), Deny: append([]string(nil), p.Deny...),
		MaxKeys: p.MaxKeys, MaxValueBytes: p.MaxValueBytes, MaxBytes: p.MaxBytes,
		MaxStdoutBytes: p.MaxStdoutBytes, MaxStderrBytes: p.MaxStderrBytes,
		QueueTimeout: p.QueueTimeout.Duration, EvaluationTimeout: p.EvaluationTimeout.Duration,
	}
}

func DirenvImportAllowed(p ResolvedDirenvImportPolicy, name string) bool {
	upper := strings.ToUpper(name)
	if DirenvImportImmutableDenied(upper) || matchDirenvPattern(p.Deny, upper) {
		return false
	}
	return matchDirenvPattern(p.Allow, upper)
}

func matchDirenvPattern(patterns []string, upperName string) bool {
	for _, pattern := range patterns {
		g, err := glob.Compile(strings.ToUpper(pattern))
		if err == nil && g.Match(upperName) {
			return true
		}
	}
	return false
}

// DirenvImportImmutableDenied is intentionally non-configurable. Matching is
// case-insensitive and covers credentials, supervisor controls, runtime
// identity/location, proxies, SSH controls, and code-loading hooks.
func DirenvImportImmutableDenied(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	for _, prefix := range []string{
		"AGENTSH_", "PI_AGENTSH_", "PI_AUTO_", "PI_CODING_AGENT", "PI_SUPERVISED",
		"LD_", "DYLD_",
	} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	for _, exact := range []string{
		"HOME", "USER", "LOGNAME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
		"TMPDIR", "TEMP", "TMP", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "AZURE_OPENAI_BASE_URL",
		"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "MAILPATH", "PROMPT_COMMAND",
		"NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE",
		"RUBYLIB", "RUBYOPT", "PERL5LIB", "PERL5OPT", "PERLLIB",
		"AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID",
		"AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID", "KUBECONFIG", "GITHUB_TOKEN", "GH_TOKEN",
		"DOCKER_HOST", "DOCKER_TLS_VERIFY", "NPM_TOKEN", "NPM_CONFIG_USERCONFIG", "NETRC",
	} {
		if n == exact {
			return true
		}
	}
	for _, pattern := range []string{"*_SECRET*", "*_PASSWORD*", "*_PRIVATE_KEY*", "*_API_KEY*", "*_ACCESS_KEY*", "*_TOKEN", "*_PROXY"} {
		g, _ := glob.Compile(pattern)
		if g.Match(n) {
			return true
		}
	}
	return false
}
