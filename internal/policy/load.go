package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func validateYAMLMappingFields(value *yaml.Node, typeName string, allowed map[string]struct{}) error {
	var validate func(*yaml.Node, map[*yaml.Node]struct{}) error
	validate = func(node *yaml.Node, seen map[*yaml.Node]struct{}) error {
		if node == nil {
			return nil
		}
		if _, ok := seen[node]; ok {
			return nil
		}
		seen[node] = struct{}{}

		switch node.Kind {
		case yaml.DocumentNode:
			if len(node.Content) == 1 {
				return validate(node.Content[0], seen)
			}
		case yaml.AliasNode:
			return validate(node.Alias, seen)
		case yaml.SequenceNode:
			for _, child := range node.Content {
				if err := validate(child, seen); err != nil {
					return err
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, field := node.Content[i], node.Content[i+1]
				if key.Value == "<<" {
					if err := validate(field, seen); err != nil {
						return err
					}
					continue
				}
				if _, ok := allowed[key.Value]; !ok {
					return fmt.Errorf("field %s not found in type %s", key.Value, typeName)
				}
			}
		}
		return nil
	}
	return validate(value, make(map[*yaml.Node]struct{}))
}

func LoadFromFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return LoadFromBytes(b)
}

// LoadFromBytes parses and validates a policy from raw YAML bytes.
func LoadFromBytes(b []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return &p, nil
}

func ResolvePolicyPath(dir, name string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("policy dir is empty")
	}
	if !nameRe.MatchString(name) {
		return "", fmt.Errorf("invalid policy name")
	}
	try := []string{
		filepath.Join(dir, name+".yaml"),
		filepath.Join(dir, name+".yml"),
		filepath.Join(dir, name),
	}
	for _, p := range try {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("policy %q not found in %q", name, dir)
}
