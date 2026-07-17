package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultProjectOverlayGlob = ".agentsh/policy-overlays/*.yaml"

var overlayNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ProjectOverlaysConfig is the policy package's minimal view of the AgentSH
// project overlay configuration.
type ProjectOverlaysConfig struct {
	Enabled         bool
	Paths           []string
	RequireApproval bool
	OnDenied        string
}

// PolicyOverlay is a restricted policy fragment that may add rule lists to a
// trusted base policy. It intentionally excludes top-level Policy settings such
// as version, audit, resources, metadata, and providers.
type PolicyOverlay struct {
	Name                 string                `yaml:"name"`
	FileRules            []FileRule            `yaml:"file_rules,omitempty"`
	NetworkRules         []NetworkRule         `yaml:"network_rules,omitempty"`
	CommandRules         []CommandRule         `yaml:"command_rules,omitempty"`
	UnixRules            []UnixSocketRule      `yaml:"unix_socket_rules,omitempty"`
	SignalRules          []SignalRule          `yaml:"signal_rules,omitempty"`
	DnsRedirectRules     []DnsRedirectRule     `yaml:"dns_redirects,omitempty"`
	ConnectRedirectRules []ConnectRedirectRule `yaml:"connect_redirects,omitempty"`
	PackageRules         []PackageRule         `yaml:"package_rules,omitempty"`
}

// OverlayFile ties an on-disk overlay file to its parsed fragment.
type OverlayFile struct {
	AbsPath string
	RelPath string
	Overlay PolicyOverlay
}

// LoadOverlay parses and validates a project-local policy overlay fragment.
func LoadOverlay(path string) (*PolicyOverlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read overlay: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var overlay PolicyOverlay
	if err := dec.Decode(&overlay); err != nil {
		return nil, fmt.Errorf("parse overlay: %w", err)
	}
	if err := overlay.Validate(); err != nil {
		return nil, fmt.Errorf("validate overlay: %w", err)
	}
	return &overlay, nil
}

// DiscoverProjectOverlays evaluates relative glob patterns beneath projectRoot,
// parses matching overlays, and returns them in deterministic path order.
func DiscoverProjectOverlays(projectRoot string, cfg ProjectOverlaysConfig) ([]OverlayFile, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if strings.TrimSpace(projectRoot) == "" {
		return nil, fmt.Errorf("project root is empty")
	}
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	if eval, err := filepath.EvalSymlinks(root); err == nil {
		root = eval
	} else {
		return nil, fmt.Errorf("resolve project root symlinks: %w", err)
	}
	patterns := cfg.Paths
	if len(patterns) == 0 {
		patterns = []string{DefaultProjectOverlayGlob}
	}
	var matches []string
	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		clean, err := cleanOverlayPattern(pattern)
		if err != nil {
			return nil, err
		}
		globPattern := filepath.Join(root, clean)
		paths, err := filepath.Glob(globPattern)
		if err != nil {
			return nil, fmt.Errorf("overlay glob %q: %w", pattern, err)
		}
		for _, path := range paths {
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil, fmt.Errorf("resolve overlay path %q: %w", path, err)
			}
			abs = filepath.Clean(abs)
			if !pathWithin(abs, root) {
				return nil, fmt.Errorf("overlay path %q escapes project root %q", path, root)
			}
			if eval, err := filepath.EvalSymlinks(abs); err == nil {
				if !pathWithin(eval, root) {
					return nil, fmt.Errorf("overlay path %q resolves outside project root %q", path, root)
				}
			} else {
				return nil, fmt.Errorf("resolve overlay path symlinks %q: %w", path, err)
			}
			if _, ok := seen[abs]; ok {
				continue
			}
			seen[abs] = struct{}{}
			matches = append(matches, abs)
		}
	}
	sort.Strings(matches)

	out := make([]OverlayFile, 0, len(matches))
	for _, abs := range matches {
		overlay, err := LoadOverlay(abs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", abs, err)
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			return nil, fmt.Errorf("relativize overlay path %q: %w", abs, err)
		}
		out = append(out, OverlayFile{AbsPath: abs, RelPath: filepath.ToSlash(rel), Overlay: *overlay})
	}
	return out, nil
}

func cleanOverlayPattern(pattern string) (string, error) {
	if pattern == "" {
		return "", fmt.Errorf("overlay path pattern must not be empty")
	}
	if filepath.IsAbs(pattern) {
		return "", fmt.Errorf("overlay path pattern %q must be relative", pattern)
	}
	clean := filepath.Clean(pattern)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("overlay path pattern %q must not traverse outside the project root", pattern)
	}
	return clean, nil
}

func pathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Validate performs overlay-specific validation before the fragment is merged.
func (o PolicyOverlay) Validate() error {
	if o.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !overlayNameRe.MatchString(o.Name) {
		return fmt.Errorf("name %q must match %s", o.Name, overlayNameRe.String())
	}
	if o.ruleCount() == 0 {
		return fmt.Errorf("at least one rule list must be non-empty")
	}
	if err := rejectDuplicateOverlayRuleNames(o); err != nil {
		return err
	}
	if err := rejectProjectOverlayBoundaries(o); err != nil {
		return err
	}
	probe := Policy{
		Version:              1,
		Name:                 "overlay-" + o.Name,
		FileRules:            append([]FileRule(nil), o.FileRules...),
		NetworkRules:         append([]NetworkRule(nil), o.NetworkRules...),
		CommandRules:         append([]CommandRule(nil), o.CommandRules...),
		UnixRules:            append([]UnixSocketRule(nil), o.UnixRules...),
		SignalRules:          append([]SignalRule(nil), o.SignalRules...),
		DnsRedirectRules:     append([]DnsRedirectRule(nil), o.DnsRedirectRules...),
		ConnectRedirectRules: append([]ConnectRedirectRule(nil), o.ConnectRedirectRules...),
		PackageRules:         append([]PackageRule(nil), o.PackageRules...),
	}
	if err := probe.Validate(); err != nil {
		return err
	}
	return nil
}

func (o PolicyOverlay) ruleCount() int {
	return len(o.FileRules) + len(o.NetworkRules) + len(o.CommandRules) + len(o.UnixRules) + len(o.SignalRules) + len(o.DnsRedirectRules) + len(o.ConnectRedirectRules) + len(o.PackageRules)
}

func rejectProjectOverlayBoundaries(o PolicyOverlay) error {
	for _, rule := range o.FileRules {
		if rule.ProjectOverlayBoundary {
			return fmt.Errorf("file_rules rule %q must not set project_overlay_boundary", rule.Name)
		}
	}
	for _, rule := range o.NetworkRules {
		if rule.ProjectOverlayBoundary {
			return fmt.Errorf("network_rules rule %q must not set project_overlay_boundary", rule.Name)
		}
	}
	for _, rule := range o.CommandRules {
		if rule.ProjectOverlayBoundary {
			return fmt.Errorf("command_rules rule %q must not set project_overlay_boundary", rule.Name)
		}
	}
	for _, rule := range o.UnixRules {
		if rule.ProjectOverlayBoundary {
			return fmt.Errorf("unix_socket_rules rule %q must not set project_overlay_boundary", rule.Name)
		}
	}
	for _, rule := range o.SignalRules {
		if rule.ProjectOverlayBoundary {
			return fmt.Errorf("signal_rules rule %q must not set project_overlay_boundary", rule.Name)
		}
	}
	return nil
}

func rejectDuplicateOverlayRuleNames(o PolicyOverlay) error {
	seen := map[string]string{}
	check := func(family, name string) error {
		if name == "" {
			return fmt.Errorf("%s rule name is required", family)
		}
		if prev, ok := seen[name]; ok {
			return fmt.Errorf("duplicate overlay rule name %q in %s and %s", name, prev, family)
		}
		seen[name] = family
		return nil
	}
	for _, r := range o.FileRules {
		if err := check("file_rules", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.NetworkRules {
		if err := check("network_rules", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.CommandRules {
		if err := check("command_rules", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.UnixRules {
		if err := check("unix_socket_rules", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.SignalRules {
		if err := check("signal_rules", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.DnsRedirectRules {
		if err := check("dns_redirects", r.Name); err != nil {
			return err
		}
	}
	for _, r := range o.ConnectRedirectRules {
		if err := check("connect_redirects", r.Name); err != nil {
			return err
		}
	}
	return nil
}

// MergePolicyOverlays returns a cloned base policy with overlay rules merged
// before each trusted base policy's explicit project-overlay boundary. Policies
// without an explicit boundary retain the legacy behavior of inserting before a
// terminal catch-all/default deny.
func MergePolicyOverlays(base *Policy, overlays []PolicyOverlay) (*Policy, error) {
	if base == nil {
		return nil, fmt.Errorf("base policy is nil")
	}
	merged := clonePolicyForOverlay(base)
	knownRules := clonePolicyForOverlay(base)
	var added PolicyOverlay
	for _, overlay := range overlays {
		if err := overlay.Validate(); err != nil {
			return nil, fmt.Errorf("overlay %q: %w", overlay.Name, err)
		}
		if err := rejectBaseRuleNameConflicts(knownRules, overlay); err != nil {
			return nil, fmt.Errorf("overlay %q: %w", overlay.Name, err)
		}
		appendOverlayRuleLists(knownRules, overlay)
		appendPolicyOverlayRuleLists(&added, overlay)
	}

	// Insert each family's complete overlay block once. Besides preserving the
	// deterministic overlay-file order, this prevents a terminal-shaped rule in
	// one overlay from becoming the insertion point for a later overlay.
	merged.FileRules = insertFileOverlayRules(merged.FileRules, added.FileRules)
	merged.CommandRules = insertCommandOverlayRules(merged.CommandRules, added.CommandRules)
	merged.NetworkRules = insertNetworkOverlayRules(merged.NetworkRules, added.NetworkRules)
	merged.UnixRules = insertUnixOverlayRules(merged.UnixRules, added.UnixRules)
	merged.SignalRules = insertSignalOverlayRules(merged.SignalRules, added.SignalRules)
	merged.DnsRedirectRules = append(merged.DnsRedirectRules, added.DnsRedirectRules...)
	merged.ConnectRedirectRules = append(merged.ConnectRedirectRules, added.ConnectRedirectRules...)
	merged.PackageRules = append(merged.PackageRules, added.PackageRules...)
	if err := merged.Validate(); err != nil {
		return nil, fmt.Errorf("validate merged policy: %w", err)
	}
	return merged, nil
}

func appendPolicyOverlayRuleLists(dst *PolicyOverlay, src PolicyOverlay) {
	dst.FileRules = append(dst.FileRules, src.FileRules...)
	dst.NetworkRules = append(dst.NetworkRules, src.NetworkRules...)
	dst.CommandRules = append(dst.CommandRules, src.CommandRules...)
	dst.UnixRules = append(dst.UnixRules, src.UnixRules...)
	dst.SignalRules = append(dst.SignalRules, src.SignalRules...)
	dst.DnsRedirectRules = append(dst.DnsRedirectRules, src.DnsRedirectRules...)
	dst.ConnectRedirectRules = append(dst.ConnectRedirectRules, src.ConnectRedirectRules...)
	dst.PackageRules = append(dst.PackageRules, src.PackageRules...)
}

func appendOverlayRuleLists(dst *Policy, src PolicyOverlay) {
	dst.FileRules = append(dst.FileRules, src.FileRules...)
	dst.NetworkRules = append(dst.NetworkRules, src.NetworkRules...)
	dst.CommandRules = append(dst.CommandRules, src.CommandRules...)
	dst.UnixRules = append(dst.UnixRules, src.UnixRules...)
	dst.SignalRules = append(dst.SignalRules, src.SignalRules...)
	dst.DnsRedirectRules = append(dst.DnsRedirectRules, src.DnsRedirectRules...)
	dst.ConnectRedirectRules = append(dst.ConnectRedirectRules, src.ConnectRedirectRules...)
	dst.PackageRules = append(dst.PackageRules, src.PackageRules...)
}

func clonePolicyForOverlay(p *Policy) *Policy {
	c := *p
	c.Metadata = append([]RuleMetadata(nil), p.Metadata...)
	c.FileRules = append([]FileRule(nil), p.FileRules...)
	c.NetworkRules = append([]NetworkRule(nil), p.NetworkRules...)
	c.CommandRules = append([]CommandRule(nil), p.CommandRules...)
	c.UnixRules = append([]UnixSocketRule(nil), p.UnixRules...)
	c.RegistryRules = append([]RegistryRule(nil), p.RegistryRules...)
	c.SignalRules = append([]SignalRule(nil), p.SignalRules...)
	c.DnsRedirectRules = append([]DnsRedirectRule(nil), p.DnsRedirectRules...)
	c.ConnectRedirectRules = append([]ConnectRedirectRule(nil), p.ConnectRedirectRules...)
	c.PackageRules = append([]PackageRule(nil), p.PackageRules...)
	c.HTTPServices = append([]HTTPService(nil), p.HTTPServices...)
	return &c
}

func rejectBaseRuleNameConflicts(base *Policy, overlay PolicyOverlay) error {
	checkFamily := func(family string, existing []string, added []string) error {
		seen := map[string]struct{}{}
		for _, name := range existing {
			if name != "" {
				seen[name] = struct{}{}
			}
		}
		for _, name := range added {
			if _, ok := seen[name]; ok {
				return fmt.Errorf("rule name %q already exists in %s", name, family)
			}
			seen[name] = struct{}{}
		}
		return nil
	}
	if err := checkFamily("file_rules", fileRuleNames(base.FileRules), fileRuleNames(overlay.FileRules)); err != nil {
		return err
	}
	if err := checkFamily("network_rules", networkRuleNames(base.NetworkRules), networkRuleNames(overlay.NetworkRules)); err != nil {
		return err
	}
	if err := checkFamily("command_rules", commandRuleNames(base.CommandRules), commandRuleNames(overlay.CommandRules)); err != nil {
		return err
	}
	if err := checkFamily("unix_socket_rules", unixRuleNames(base.UnixRules), unixRuleNames(overlay.UnixRules)); err != nil {
		return err
	}
	if err := checkFamily("signal_rules", signalRuleNames(base.SignalRules), signalRuleNames(overlay.SignalRules)); err != nil {
		return err
	}
	if err := checkFamily("dns_redirects", dnsRuleNames(base.DnsRedirectRules), dnsRuleNames(overlay.DnsRedirectRules)); err != nil {
		return err
	}
	if err := checkFamily("connect_redirects", connectRuleNames(base.ConnectRedirectRules), connectRuleNames(overlay.ConnectRedirectRules)); err != nil {
		return err
	}
	return nil
}

func fileRuleNames(rs []FileRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func networkRuleNames(rs []NetworkRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func commandRuleNames(rs []CommandRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func unixRuleNames(rs []UnixSocketRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func signalRuleNames(rs []SignalRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func dnsRuleNames(rs []DnsRedirectRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
func connectRuleNames(rs []ConnectRedirectRule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

func projectOverlayInsertionIndex[T any](base []T, isBoundary, isTerminalDeny func(T) bool) int {
	for i, rule := range base {
		if isBoundary(rule) {
			return i
		}
	}
	for i, rule := range base {
		if isTerminalDeny(rule) {
			return i
		}
	}
	return len(base)
}

func insertFileOverlayRules(base []FileRule, added []FileRule) []FileRule {
	if len(added) == 0 {
		return base
	}
	idx := projectOverlayInsertionIndex(base,
		func(rule FileRule) bool { return rule.ProjectOverlayBoundary },
		isTerminalFileDeny,
	)
	out := make([]FileRule, 0, len(base)+len(added))
	out = append(out, base[:idx]...)
	out = append(out, added...)
	out = append(out, base[idx:]...)
	return out
}

func insertCommandOverlayRules(base []CommandRule, added []CommandRule) []CommandRule {
	if len(added) == 0 {
		return base
	}
	idx := projectOverlayInsertionIndex(base,
		func(rule CommandRule) bool { return rule.ProjectOverlayBoundary },
		isTerminalCommandDeny,
	)
	out := make([]CommandRule, 0, len(base)+len(added))
	out = append(out, base[:idx]...)
	out = append(out, added...)
	out = append(out, base[idx:]...)
	return out
}

func insertNetworkOverlayRules(base []NetworkRule, added []NetworkRule) []NetworkRule {
	if len(added) == 0 {
		return base
	}
	idx := projectOverlayInsertionIndex(base,
		func(rule NetworkRule) bool { return rule.ProjectOverlayBoundary },
		isTerminalNetworkDeny,
	)
	out := make([]NetworkRule, 0, len(base)+len(added))
	out = append(out, base[:idx]...)
	out = append(out, added...)
	out = append(out, base[idx:]...)
	return out
}

func insertUnixOverlayRules(base []UnixSocketRule, added []UnixSocketRule) []UnixSocketRule {
	if len(added) == 0 {
		return base
	}
	idx := projectOverlayInsertionIndex(base,
		func(rule UnixSocketRule) bool { return rule.ProjectOverlayBoundary },
		isTerminalUnixDeny,
	)
	out := make([]UnixSocketRule, 0, len(base)+len(added))
	out = append(out, base[:idx]...)
	out = append(out, added...)
	out = append(out, base[idx:]...)
	return out
}

func insertSignalOverlayRules(base []SignalRule, added []SignalRule) []SignalRule {
	if len(added) == 0 {
		return base
	}
	idx := projectOverlayInsertionIndex(base,
		func(rule SignalRule) bool { return rule.ProjectOverlayBoundary },
		isTerminalSignalDeny,
	)
	out := make([]SignalRule, 0, len(base)+len(added))
	out = append(out, base[:idx]...)
	out = append(out, added...)
	out = append(out, base[idx:]...)
	return out
}

func isTerminalFileDeny(rule FileRule) bool {
	if strings.HasPrefix(rule.Name, "default-deny") && rule.Decision == "deny" {
		return true
	}
	return rule.Decision == "deny" && len(rule.Paths) == 1 && rule.Paths[0] == "**" && len(rule.Operations) == 1 && rule.Operations[0] == "*"
}

func isTerminalCommandDeny(rule CommandRule) bool {
	if strings.HasPrefix(rule.Name, "default-deny") && rule.Decision == "deny" {
		return true
	}
	return rule.Decision == "deny" && len(rule.Commands) == 0 && len(rule.ArgsPatterns) == 0
}

func isTerminalNetworkDeny(rule NetworkRule) bool {
	if strings.HasPrefix(rule.Name, "default-deny") && rule.Decision == "deny" {
		return true
	}
	return rule.Decision == "deny" && len(rule.Domains) == 1 && rule.Domains[0] == "*" && len(rule.Ports) == 0 && len(rule.CIDRs) == 0
}

func isTerminalUnixDeny(rule UnixSocketRule) bool {
	if strings.HasPrefix(rule.Name, "default-deny") && rule.Decision == "deny" {
		return true
	}
	return rule.Decision == "deny" && len(rule.Paths) == 1 && rule.Paths[0] == "**" && len(rule.Operations) == 0
}

func isTerminalSignalDeny(rule SignalRule) bool {
	return strings.HasPrefix(rule.Name, "default-deny") && rule.Decision == "deny"
}

// HashEffectivePolicy returns a stable SHA-256 hash of the YAML encoding of p.
func HashEffectivePolicy(p *Policy) (string, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
