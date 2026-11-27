package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxExtendsDepth is the longest allowed chain of extends.
const maxExtendsDepth = 8

// PolicyNames is a list of policy names. In YAML it can be a single name or a list.
type PolicyNames []string

func (n *PolicyNames) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag == "!!null" {
			*n = nil
			return nil
		}
		*n = PolicyNames{value.Value}
		return nil
	case yaml.SequenceNode:
		var names []string
		if err := value.Decode(&names); err != nil {
			return err
		}
		*n = names
		return nil
	default:
		return fmt.Errorf("extends must be a policy name or a list of policy names")
	}
}

// inheritedRuleCounts is how many rules at the start of each list came from
// base policies. Project overlay rules go after them.
type inheritedRuleCounts struct {
	file, network, command, unix, signal int
}

// ReadFunc reads a policy file. Callers do their manifest and signature checks
// here. It is called for the policy and for each of its bases.
type ReadFunc func(path string) ([]byte, error)

// LoadFile loads the policy at path. Bases named in extends are looked up in the
// same directory and read with read, so they get the same checks.
func LoadFile(path string, read ReadFunc) (*Policy, error) {
	data, err := read(path)
	if err != nil {
		return nil, err
	}
	top, err := parsePolicyLayer(data)
	if err != nil {
		return nil, err
	}
	p := top.policy
	if len(p.Extends) > 0 {
		r := &extendsResolver{dir: filepath.Dir(path), read: read, done: map[string]bool{}}
		top.name = policyNameFromPath(path)
		if err := r.visit(
			top,
			[]extendsFrame{{name: top.name, path: filepath.Clean(path)}},
		); err != nil {
			return nil, err
		}
		if p, err = mergeLayers(r.order); err != nil {
			return nil, err
		}
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return p, nil
}

// policyLayer is one policy file in an extends chain.
type policyLayer struct {
	name   string
	policy *Policy
	keys   map[string]bool // top-level YAML keys present in the file
}

// set reports whether the file sets the top-level section key.
func (l *policyLayer) set(key string, value any) bool {
	return l.keys[key] || !reflect.ValueOf(value).IsZero()
}

func parsePolicyLayer(b []byte) (*policyLayer, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	keys := map[string]bool{}
	if len(doc.Content) == 1 && doc.Content[0].Kind == yaml.MappingNode {
		m := doc.Content[0]
		for i := 0; i+1 < len(m.Content); i += 2 {
			keys[m.Content[i].Value] = true
		}
	}
	return &policyLayer{policy: &p, keys: keys}, nil
}

func policyNameFromPath(path string) string {
	base := filepath.Base(path)
	for _, ext := range []string{".yaml", ".yml"} {
		if strings.HasSuffix(base, ext) {
			return strings.TrimSuffix(base, ext)
		}
	}
	return base
}

type extendsFrame struct{ name, path string }

// extendsResolver loads the bases depth-first and puts them in order: each base
// comes before the policies that extend it, bases keep their listed order, and a
// base that appears twice is only kept the first time.
type extendsResolver struct {
	dir   string
	read  ReadFunc
	done  map[string]bool // resolved paths already in order
	order []*policyLayer
}

func (r *extendsResolver) visit(layer *policyLayer, stack []extendsFrame) error {
	for _, baseName := range layer.policy.Extends {
		prefix := fmt.Sprintf("policy %q extends %q", layer.name, baseName)
		path, err := ResolvePolicyPath(r.dir, baseName)
		if err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		path = filepath.Clean(path)
		for i, f := range stack {
			if f.path == path {
				chain := make([]string, 0, len(stack)-i+1)
				for _, f := range stack[i:] {
					chain = append(chain, f.name)
				}
				return fmt.Errorf(
					"policy extends cycle: %s -> %s",
					strings.Join(chain, " -> "),
					baseName,
				)
			}
		}
		if r.done[path] {
			continue
		}
		if len(stack) > maxExtendsDepth {
			return fmt.Errorf("%s: policy extends depth exceeds %d", prefix, maxExtendsDepth)
		}
		data, err := r.read(path)
		if err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		base, err := parsePolicyLayer(data)
		if err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		base.name = baseName
		if err := r.visit(
			base,
			append(stack, extendsFrame{name: baseName, path: path}),
		); err != nil {
			return err
		}
	}
	r.done[stack[len(stack)-1].path] = true
	r.order = append(r.order, layer)
	return nil
}

// mergeLayers merges the ordered layers. The last one is the policy itself.
// Rule lists are joined in order and a rule name may only be used by one layer.
// A section set by a later layer replaces an earlier one. Map keys must be
// unique across layers.
func mergeLayers(layers []*policyLayer) (*Policy, error) {
	out := &Policy{}
	names := map[string]map[string]string{}
	for i, l := range layers {
		p := l.policy
		if i == len(layers)-1 {
			out.inherited = inheritedRuleCounts{
				file:    len(out.FileRules),
				network: len(out.NetworkRules),
				command: len(out.CommandRules),
				unix:    len(out.UnixRules),
				signal:  len(out.SignalRules),
			}
		} else {
			p = withoutOverlayBoundaries(p)
		}

		var err error
		out.Metadata = append(out.Metadata, p.Metadata...)
		out.PackageRules = append(out.PackageRules, p.PackageRules...)
		if out.FileRules, err = mergeRules(
			names,
			"file_rules",
			l.name,
			out.FileRules,
			p.FileRules,
			func(r FileRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.NetworkRules, err = mergeRules(
			names,
			"network_rules",
			l.name,
			out.NetworkRules,
			p.NetworkRules,
			func(r NetworkRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.CommandRules, err = mergeRules(
			names,
			"command_rules",
			l.name,
			out.CommandRules,
			p.CommandRules,
			func(r CommandRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.UnixRules, err = mergeRules(
			names,
			"unix_socket_rules",
			l.name,
			out.UnixRules,
			p.UnixRules,
			func(r UnixSocketRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.RegistryRules, err = mergeRules(
			names,
			"registry_rules",
			l.name,
			out.RegistryRules,
			p.RegistryRules,
			func(r RegistryRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.SignalRules, err = mergeRules(
			names,
			"signal_rules",
			l.name,
			out.SignalRules,
			p.SignalRules,
			func(r SignalRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.DnsRedirectRules, err = mergeRules(
			names,
			"dns_redirects",
			l.name,
			out.DnsRedirectRules,
			p.DnsRedirectRules,
			func(r DnsRedirectRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.ConnectRedirectRules, err = mergeRules(
			names,
			"connect_redirects",
			l.name,
			out.ConnectRedirectRules,
			p.ConnectRedirectRules,
			func(r ConnectRedirectRule) string { return r.Name },
		); err != nil {
			return nil, err
		}
		if out.HTTPServices, err = mergeRules(
			names,
			"http_services",
			l.name,
			out.HTTPServices,
			p.HTTPServices,
			func(r HTTPService) string { return r.Name },
		); err != nil {
			return nil, err
		}

		if out.EnvInject, err = mergeMap(
			names,
			"env_inject",
			l.name,
			out.EnvInject,
			p.EnvInject,
		); err != nil {
			return nil, err
		}
		if out.Providers, err = mergeMap(
			names,
			"providers",
			l.name,
			out.Providers,
			p.Providers,
		); err != nil {
			return nil, err
		}
		if out.ProcessContexts, err = mergeMap(
			names,
			"process_contexts",
			l.name,
			out.ProcessContexts,
			p.ProcessContexts,
		); err != nil {
			return nil, err
		}
		if out.ProcessIdentities, err = mergeMap(
			names,
			"process_identities",
			l.name,
			out.ProcessIdentities,
			p.ProcessIdentities,
		); err != nil {
			return nil, err
		}

		replace(l, "resource_limits", &out.ResourceLimits, p.ResourceLimits)
		replace(l, "env_policy", &out.EnvPolicy, p.EnvPolicy)
		replace(l, "direnv", &out.Direnv, p.Direnv)
		replace(l, "audit", &out.Audit, p.Audit)
		replace(l, "mcp_rules", &out.MCPRules, p.MCPRules)
		replace(l, "transparent_commands", &out.TransparentCommands, p.TransparentCommands)
		replace(l, "services", &out.Services, p.Services)
		replace(l, "db_services", &out.DBServices, p.DBServices)
		replace(l, "database_rules", &out.DatabaseRules, p.DatabaseRules)
		replace(
			l,
			"database_connection_rules",
			&out.DatabaseConnectionRules,
			p.DatabaseConnectionRules,
		)
		replace(l, "policies", &out.Policies, p.Policies)
	}
	top := layers[len(layers)-1].policy
	out.Version = top.Version
	out.Name = top.Name
	out.Description = top.Description
	out.Extends = top.Extends
	return out, nil
}

func replace[T any](l *policyLayer, key string, dst *T, src T) {
	if l.set(key, src) {
		*dst = src
	}
}

func mergeRules[T any](
	names map[string]map[string]string,
	family, owner string,
	dst, src []T,
	name func(T) string,
) ([]T, error) {
	defined := names[family]
	if defined == nil {
		defined = map[string]string{}
		names[family] = defined
	}
	for _, r := range src {
		n := name(r)
		if n == "" {
			continue
		}
		if prev, ok := defined[n]; ok && prev != owner {
			return nil, fmt.Errorf(
				"policy %q: %s rule %q is already defined by base policy %q",
				owner,
				family,
				n,
				prev,
			)
		}
		defined[n] = owner
	}
	return append(dst, src...), nil
}

func mergeMap[V any](
	names map[string]map[string]string,
	section, owner string,
	dst, src map[string]V,
) (map[string]V, error) {
	if len(src) == 0 {
		return dst, nil
	}
	defined := names[section]
	if defined == nil {
		defined = map[string]string{}
		names[section] = defined
	}
	if dst == nil {
		dst = make(map[string]V, len(src))
	}
	for k, v := range src {
		if prev, ok := defined[k]; ok {
			return nil, fmt.Errorf(
				"policy %q: %s key %q is already defined by base policy %q",
				owner,
				section,
				k,
				prev,
			)
		}
		defined[k] = owner
		dst[k] = v
	}
	return dst, nil
}

// withoutOverlayBoundaries returns a copy of a base policy with
// project_overlay_boundary cleared. A base's boundary only counts when the base
// is selected directly.
func withoutOverlayBoundaries(p *Policy) *Policy {
	c := clonePolicyForOverlay(p)
	for i := range c.FileRules {
		c.FileRules[i].ProjectOverlayBoundary = false
	}
	for i := range c.NetworkRules {
		c.NetworkRules[i].ProjectOverlayBoundary = false
	}
	for i := range c.CommandRules {
		c.CommandRules[i].ProjectOverlayBoundary = false
	}
	for i := range c.UnixRules {
		c.UnixRules[i].ProjectOverlayBoundary = false
	}
	for i := range c.SignalRules {
		c.SignalRules[i].ProjectOverlayBoundary = false
	}
	return c
}

// LoadFromFile loads the policy at path and its bases without extra checks.
func LoadFromFile(path string) (*Policy, error) {
	return LoadFile(path, readPolicyFile)
}

func readPolicyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return b, nil
}
