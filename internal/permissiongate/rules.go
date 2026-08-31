package permissiongate

import "regexp"

// Match describes one dangerous-command guard that matched a Bash source.
type Match struct {
	Label string
}

type dangerousRule struct {
	pattern *regexp.Regexp
	label   string
}

// These guards intentionally preserve the legacy pi-agent-extensions
// permission-gate behavior. AgentSH owns them now so the launched Pi only
// transports authorization requests and renders prompt metadata.
var dangerousRules = []dangerousRule{
	{pattern: regexp.MustCompile(`\brm\s+(-[^\s]*r|--recursive)`), label: "recursive delete"},
	{pattern: regexp.MustCompile(`\bsudo\b`), label: "sudo"},
	{pattern: regexp.MustCompile(`\bssh\b`), label: "ssh"},
	{pattern: regexp.MustCompile(`\bchmod\b.*777`), label: "world-writable permissions"},
	{pattern: regexp.MustCompile(`>\s*/dev/[sh]d[a-z]`), label: "raw device redirect"},
	{pattern: regexp.MustCompile(`\bgit\s+push\s+.*(-f\b|--force\b)`), label: "force push"},
	{pattern: regexp.MustCompile(`\bgit\s+reset\s+--hard\b`), label: "hard reset"},
	{pattern: regexp.MustCompile(`\bgit\s+clean\s+-[^\s]*f`), label: "git clean"},
	{pattern: regexp.MustCompile(`\bgit\s+checkout\s+(\S+\s+)?--\s`), label: "git checkout (reset files)"},
	{pattern: regexp.MustCompile(`\bgit\s+checkout\s+\.\s*($|[;&|])`), label: "git checkout (reset all files)"},
	{pattern: regexp.MustCompile(`\bgit\s+restore\b`), label: "git restore"},
	{pattern: regexp.MustCompile(`\bclan\s+machines\s+update\b`), label: "deploy to machine"},
	{pattern: regexp.MustCompile(`\bcurl\b.*\|\s*(ba)?sh\b`), label: "pipe curl to shell"},
	{pattern: regexp.MustCompile(`\bwget\b.*\|\s*(ba)?sh\b`), label: "pipe wget to shell"},
	{pattern: regexp.MustCompile(`\bgh\s+issue\s+create\b`), label: "create GitHub issue"},
	{pattern: regexp.MustCompile(`\bgh\s+issue\s+(close|delete|edit|comment)\b`), label: "modify GitHub issue"},
	{pattern: regexp.MustCompile(`\bgh\s+pr\s+create\b`), label: "create GitHub PR"},
	{pattern: regexp.MustCompile(`\bgh\s+pr\s+(close|merge|edit|comment|review)\b`), label: "modify GitHub PR"},
	{pattern: regexp.MustCompile(`\bgh\s+repo\s+(create|delete|rename|archive)\b`), label: "modify GitHub repo"},
	{pattern: regexp.MustCompile(`\bgh\s+release\s+(create|delete|edit)\b`), label: "modify GitHub release"},
	{pattern: regexp.MustCompile(`\btea\s+(issue|pr)\s+create\b`), label: "create Gitea issue/PR"},
	{pattern: regexp.MustCompile(`\btea\s+(issue|pr)\s+(close|edit)\b`), label: "modify Gitea issue/PR"},
	{pattern: regexp.MustCompile(`\btea\s+comment\b`), label: "Gitea comment"},
	{pattern: regexp.MustCompile(`\bmsmtp\b`), label: "send email"},
}

// MatchDangerous returns every guard match in stable rule order.
func MatchDangerous(command string) []Match {
	matches := make([]Match, 0, 2)
	for _, rule := range dangerousRules {
		if rule.pattern.MatchString(command) {
			matches = append(matches, Match{Label: rule.label})
		}
	}
	return matches
}
