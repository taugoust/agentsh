package ancestry

import (
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/policy/pattern"
)

// Classifier determines the ProcessClass for process names.
type Classifier struct {
	mu       sync.RWMutex
	registry *pattern.ClassRegistry

	// Custom classification rules (checked first)
	customRules map[string]ProcessClass
}

// NewClassifier creates a new process classifier.
func NewClassifier() *Classifier {
	return &Classifier{
		registry:    pattern.NewClassRegistry(),
		customRules: make(map[string]ProcessClass),
	}
}

// AddCustomRule adds a custom classification rule.
// Custom rules take precedence over built-in class matching.
func (c *Classifier) AddCustomRule(commPattern string, class ProcessClass) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customRules[commPattern] = class
}

// RemoveCustomRule removes a custom classification rule.
func (c *Classifier) RemoveCustomRule(commPattern string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.customRules, commPattern)
}

// Classify determines the ProcessClass for a process name.
func (c *Classifier) Classify(comm string) ProcessClass {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check custom rules first (exact match)
	if class, ok := c.customRules[comm]; ok {
		return class
	}

	// Check custom rules with pattern matching
	for commPattern, class := range c.customRules {
		if pattern.IsBuiltinClass(commPattern) {
			continue // Skip class references in custom rules for now
		}
		p, err := pattern.Compile(commPattern)
		if err != nil {
			continue
		}
		if p.Match(comm) {
			return class
		}
	}

	// Check built-in classes
	if c.matchesClass("shell", comm) {
		return ClassShell
	}
	if c.matchesClass("editor", comm) {
		return ClassEditor
	}
	if c.matchesClass("agent", comm) {
		return ClassAgent
	}
	if c.matchesClass("build", comm) {
		return ClassBuildTool
	}
	if c.matchesClass("language-server", comm) {
		return ClassLanguageServer
	}
	if c.matchesClass("runtime", comm) {
		return ClassLanguageRuntime
	}

	return ClassUnknown
}

// matchesClass checks if comm matches any pattern in a class.
func (c *Classifier) matchesClass(className, comm string) bool {
	match, err := c.registry.Matches(className, comm)
	if err != nil {
		return false
	}
	return match
}

// ClassifyProcess is a convenience function using a default classifier.
func ClassifyProcess(comm string) ProcessClass {
	return DefaultClassifier.Classify(comm)
}

// DefaultClassifier is a global classifier instance.
var DefaultClassifier = NewClassifier()

// CountConsecutive counts the maximum consecutive occurrences of a class.
func CountConsecutive(classes []ProcessClass, target ProcessClass) int {
	maxCount := 0
	currentCount := 0

	for _, c := range classes {
		if c == target {
			currentCount++
			if currentCount > maxCount {
				maxCount = currentCount
			}
		} else {
			currentCount = 0
		}
	}

	return maxCount
}

// CountConsecutiveComm counts consecutive occurrences of matching process names.
func CountConsecutiveComm(via []string, patterns []string) int {
	maxCount := 0
	currentCount := 0

	for _, comm := range via {
		matches := false
		for _, p := range patterns {
			if comm == p || strings.Contains(comm, p) {
				matches = true
				break
			}
		}

		if matches {
			currentCount++
			if currentCount > maxCount {
				maxCount = currentCount
			}
		} else {
			currentCount = 0
		}
	}

	return maxCount
}
