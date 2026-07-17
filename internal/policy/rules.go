package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ContextConfig defines depth constraints for rule matching.
// It enables depth-aware policy rules - allowing different policies for
// "direct" (user-typed, depth 0) vs "nested" (script-spawned, depth 1+) commands.
type ContextConfig struct {
	MinDepth int `yaml:"min_depth"`
	MaxDepth int `yaml:"max_depth"` // -1 means unlimited
}

var contextConfigYAMLFields = map[string]struct{}{
	"min_depth": {},
	"max_depth": {},
}

// UnmarshalYAML handles both array syntax [direct, nested] and object syntax.
func (c *ContextConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var arr []string
		if err := value.Decode(&arr); err != nil {
			return err
		}
		return c.parseArray(arr)
	}

	// Use a pointer for max_depth to distinguish "not set" from "set to 0".
	type raw struct {
		MinDepth int  `yaml:"min_depth"`
		MaxDepth *int `yaml:"max_depth"`
	}
	if err := validateYAMLMappingFields(value, "policy.ContextConfig", contextConfigYAMLFields); err != nil {
		return err
	}
	var r raw
	if err := value.Decode(&r); err != nil {
		return err
	}
	c.MinDepth = r.MinDepth
	if r.MaxDepth != nil {
		c.MaxDepth = *r.MaxDepth
	} else {
		c.MaxDepth = -1 // Default to unlimited when not specified
	}
	return nil
}

func (c *ContextConfig) parseArray(arr []string) error {
	hasDirect := false
	hasNested := false
	for _, v := range arr {
		switch v {
		case "direct":
			hasDirect = true
		case "nested":
			hasNested = true
		default:
			return fmt.Errorf("unknown context value: %s", v)
		}
	}

	if hasDirect && hasNested {
		// Both = all depths
		c.MinDepth = 0
		c.MaxDepth = -1
	} else if hasDirect {
		c.MinDepth = 0
		c.MaxDepth = 0
	} else if hasNested {
		c.MinDepth = 1
		c.MaxDepth = -1
	}
	return nil
}

// DefaultContext returns a context matching all depths.
func DefaultContext() ContextConfig {
	return ContextConfig{MinDepth: 0, MaxDepth: -1}
}

// MatchesDepth returns true if depth falls within the configured range.
func (c *ContextConfig) MatchesDepth(depth int) bool {
	if depth < c.MinDepth {
		return false
	}
	if c.MaxDepth >= 0 && depth > c.MaxDepth {
		return false
	}
	return true
}
