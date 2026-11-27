// Package pnacl provides Process Network ACL (PNACL) functionality for
// per-process network access control policies.
package pnacl

import (
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
)

// MatchMode specifies how process matching is performed.
type MatchMode string

const (
	// MatchModeFlexible allows partial matches (any criterion matching is sufficient).
	MatchModeFlexible MatchMode = "flexible"
	// MatchModeStrict requires all specified criteria to match.
	MatchModeStrict MatchMode = "strict"
)

// MatchSpecificity represents how specific a match is, used for prioritization.
type MatchSpecificity int

const (
	// MatchSpecificityNone indicates no match.
	MatchSpecificityNone MatchSpecificity = iota
	// MatchSpecificityDefault indicates a default/fallback match.
	MatchSpecificityDefault
	// MatchSpecificityGlob indicates a glob pattern match.
	MatchSpecificityGlob
	// MatchSpecificityExact indicates an exact match.
	MatchSpecificityExact
)

// ProcessInfo contains information about a process for matching purposes.
type ProcessInfo struct {
	// Name is the process name (e.g., "claude-code").
	Name string
	// Path is the full executable path (e.g., "/usr/bin/claude-code").
	Path string
	// BundleID is the macOS bundle identifier (e.g., "com.anthropic.claudecode").
	BundleID string
	// PackageFamilyName is the Windows package family name.
	PackageFamilyName string
	// PID is the process ID.
	PID int
	// ParentPID is the parent process ID.
	ParentPID int
}

// ProcessMatchCriteria defines criteria for matching a process.
type ProcessMatchCriteria struct {
	// ProcessName is the process name to match (e.g., "claude-code").
	ProcessName string `yaml:"process_name,omitempty"`
	// Path is the executable path pattern with glob support (e.g., "/usr/bin/claude*").
	Path string `yaml:"path,omitempty"`
	// BundleID is the macOS bundle identifier (e.g., "com.anthropic.claudecode").
	BundleID string `yaml:"bundle_id,omitempty"`
	// PackageFamilyName is the Windows package family name.
	PackageFamilyName string `yaml:"package_family_name,omitempty"`
	// Strict enables strict matching mode where all specified criteria must match.
	Strict bool `yaml:"strict,omitempty"`
}

// ProcessMatcher matches processes against a single set of criteria.
// This is the original simple matcher for single-process matching.
type ProcessMatcher struct {
	criteria ProcessMatchCriteria
	mode     MatchMode
	pathGlob glob.Glob
}

// NewProcessMatcher creates a new ProcessMatcher from criteria.
// This is the original constructor for backward compatibility.
func NewProcessMatcher(criteria ProcessMatchCriteria) (*ProcessMatcher, error) {
	m := &ProcessMatcher{
		criteria: criteria,
		mode:     MatchModeFlexible,
	}

	if criteria.Strict {
		m.mode = MatchModeStrict
	}

	// Compile path glob if specified.
	if criteria.Path != "" {
		g, err := glob.Compile(criteria.Path, '/')
		if err != nil {
			return nil, err
		}
		m.pathGlob = g
	}

	return m, nil
}

// Matches checks if the given process info matches this matcher's criteria.
func (m *ProcessMatcher) Matches(info ProcessInfo) bool {
	if m.mode == MatchModeStrict {
		return m.matchStrictSimple(info)
	}
	return m.matchFlexibleSimple(info)
}

// matchFlexibleSimple returns true if any specified criterion matches.
func (m *ProcessMatcher) matchFlexibleSimple(info ProcessInfo) bool {
	// If no criteria are specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name.
	if m.criteria.ProcessName != "" {
		if matchProcessName(m.criteria.ProcessName, info.Name, false) {
			return true
		}
	}

	// Check path.
	if m.pathGlob != nil {
		if m.pathGlob.Match(info.Path) {
			return true
		}
	}

	// Check bundle ID (macOS).
	if m.criteria.BundleID != "" && info.BundleID != "" {
		if strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return true
		}
	}

	// Check package family name (Windows).
	if m.criteria.PackageFamilyName != "" && info.PackageFamilyName != "" {
		if strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return true
		}
	}

	return false
}

// matchStrictSimple returns true only if all specified criteria match.
func (m *ProcessMatcher) matchStrictSimple(info ProcessInfo) bool {
	// If no criteria are specified, don't match anything.
	if !hasCriteria(m.criteria) {
		return false
	}

	// Check process name if specified.
	if m.criteria.ProcessName != "" {
		if !matchProcessName(m.criteria.ProcessName, info.Name, true) {
			return false
		}
	}

	// Check path if specified.
	if m.pathGlob != nil {
		if !m.pathGlob.Match(info.Path) {
			return false
		}
	}

	// Check bundle ID if specified.
	if m.criteria.BundleID != "" {
		if !strings.EqualFold(m.criteria.BundleID, info.BundleID) {
			return false
		}
	}

	// Check package family name if specified.
	if m.criteria.PackageFamilyName != "" {
		if !strings.EqualFold(m.criteria.PackageFamilyName, info.PackageFamilyName) {
			return false
		}
	}

	return true
}

// Mode returns the matching mode for this matcher.
func (m *ProcessMatcher) Mode() MatchMode {
	return m.mode
}

// Criteria returns the match criteria for this matcher.
func (m *ProcessMatcher) Criteria() ProcessMatchCriteria {
	return m.criteria
}

// matchProcessName matches a process name against a pattern.
// When strict is false, it supports both exact match and basename extraction.
// When strict is true, it requires an exact match (case-insensitive).
func matchProcessName(pattern, name string, strict bool) bool {
	matched, _ := matchProcessNameWithSpecificity(pattern, name, strict)
	return matched
}

// matchProcessNameWithSpecificity matches a process name and returns specificity.
func matchProcessNameWithSpecificity(pattern, name string, strict bool) (bool, MatchSpecificity) {
	// Normalize to lowercase for comparison.
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)

	// Direct match (highest specificity).
	if pattern == name {
		return true, MatchSpecificityExact
	}

	// In strict mode, only exact match is allowed.
	if strict {
		return false, MatchSpecificityNone
	}

	// Match against basename (for paths passed as names).
	basename := strings.ToLower(filepath.Base(name))
	if pattern == basename {
		return true, MatchSpecificityExact
	}

	// Check if pattern contains wildcards for glob-like matching.
	if strings.ContainsAny(pattern, "*?") {
		// Use filepath.Match for simple glob patterns in process names.
		if matched, _ := filepath.Match(pattern, name); matched {
			return true, MatchSpecificityGlob
		}
		if matched, _ := filepath.Match(pattern, basename); matched {
			return true, MatchSpecificityGlob
		}
	}

	return false, MatchSpecificityNone
}

// hasCriteria returns true if at least one matching criterion is specified.
func hasCriteria(c ProcessMatchCriteria) bool {
	return c.ProcessName != "" ||
		c.Path != "" ||
		c.BundleID != "" ||
		c.PackageFamilyName != ""
}
