package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy/signing"
	"github.com/agentsh/agentsh/pkg/types"
)

// writePolicies writes name -> YAML policy files into a new temp dir.
func writePolicies(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		writePolicy(t, dir, name+".yaml", content)
	}
	return dir
}

func loadExtends(t *testing.T, dir, name string) (*Policy, error) {
	t.Helper()
	return LoadFromFile(filepath.Join(dir, name+".yaml"))
}

func mustLoadExtends(t *testing.T, dir, name string) *Policy {
	t.Helper()
	p, err := loadExtends(t, dir, name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return p
}

func wantErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want it to contain %q", err, want)
	}
}

// familyPolicy returns a policy defining one rule named <prefix>-<family> in
// every rule list.
func familyPolicy(name, extends, prefix, ip string) string {
	return `version: 1
name: ` + name + `
` + extends + `
metadata:
  - rule_name: ` + prefix + `-file
    source: ` + prefix + `
file_rules:
  - name: ` + prefix + `-file
    paths: [/` + prefix + `/**]
    operations: [read]
    decision: allow
network_rules:
  - name: ` + prefix + `-net
    domains: [` + prefix + `.example.com]
    decision: allow
command_rules:
  - name: ` + prefix + `-cmd
    commands: [` + prefix + `]
    decision: allow
unix_socket_rules:
  - name: ` + prefix + `-unix
    paths: [/run/` + prefix + `.sock]
    decision: allow
registry_rules:
  - name: ` + prefix + `-reg
    paths: ['HKLM\` + prefix + `']
    decision: allow
signal_rules:
  - name: ` + prefix + `-sig
    signals: [SIGTERM]
    target: {type: children}
    decision: allow
dns_redirects:
  - name: ` + prefix + `-dns
    match: '^` + prefix + `\.example\.com$'
    resolve_to: ` + ip + `
connect_redirects:
  - name: ` + prefix + `-connect
    match: '^` + prefix + `:443$'
    redirect_to: ` + ip + `:443
package_rules:
  - match: {packages: [` + prefix + `]}
    action: allow
http_services:
  - name: ` + prefix + `-svc
    expose_as: ` + strings.ToUpper(prefix) + `_SVC_URL
    upstream: https://` + prefix + `.example.com
    default: deny
    rules:
      - name: read
        methods: [GET]
        paths: [/]
        decision: allow
`
}

func TestExtendsBaseRulesComeFirstInEveryRuleList(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base":  familyPolicy("base", "", "base", "10.0.0.1"),
		"child": familyPolicy("child", "extends: base", "child", "10.0.0.2"),
	})
	p := mustLoadExtends(t, dir, "child")

	if p.Name != "child" || !reflect.DeepEqual([]string(p.Extends), []string{"base"}) {
		t.Fatalf("name/extends = %q/%v", p.Name, p.Extends)
	}
	check := func(family string, got []string, suffix string) {
		t.Helper()
		want := []string{"base-" + suffix, "child-" + suffix}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", family, got, want)
		}
	}
	check("file_rules", fileRuleNames(p.FileRules), "file")
	check("network_rules", networkRuleNames(p.NetworkRules), "net")
	check("command_rules", commandRuleNames(p.CommandRules), "cmd")
	check("unix_socket_rules", unixRuleNames(p.UnixRules), "unix")
	check("signal_rules", signalRuleNames(p.SignalRules), "sig")
	check("dns_redirects", dnsRuleNames(p.DnsRedirectRules), "dns")
	check("connect_redirects", connectRuleNames(p.ConnectRedirectRules), "connect")
	var reg, svc, pkg, meta []string
	for _, r := range p.RegistryRules {
		reg = append(reg, r.Name)
	}
	for _, s := range p.HTTPServices {
		svc = append(svc, s.Name)
	}
	for _, r := range p.PackageRules {
		pkg = append(pkg, r.Match.Packages[0]+"-pkg")
	}
	for _, m := range p.Metadata {
		meta = append(meta, m.RuleName)
	}
	check("registry_rules", reg, "reg")
	check("http_services", svc, "svc")
	check("package_rules", pkg, "pkg")
	if !reflect.DeepEqual(meta, []string{"base-file", "child-file"}) {
		t.Errorf("metadata = %v", meta)
	}
}

func cmdPolicy(name, extends string, rules ...string) string {
	s := "version: 1\nname: " + name + "\n"
	if extends != "" {
		s += "extends: " + extends + "\n"
	}
	s += "command_rules:\n"
	for _, r := range rules {
		s += "  - name: " + r + "\n    commands: [" + r + "]\n    decision: allow\n"
	}
	return s
}

func TestExtendsMultipleBasesKeepListedOrder(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"a":     cmdPolicy("a", "", "a1"),
		"b":     cmdPolicy("b", "", "b1"),
		"child": cmdPolicy("child", "[b, a]", "c1"),
	})
	got := commandRuleNames(mustLoadExtends(t, dir, "child").CommandRules)
	if want := []string{"b1", "a1", "c1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("command_rules = %v, want %v", got, want)
	}
}

func TestExtendsRecursiveAndDiamond(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"root":  cmdPolicy("root", "", "r1"),
		"left":  cmdPolicy("left", "root", "l1"),
		"right": cmdPolicy("right", "root", "rt1"),
		"child": cmdPolicy("child", "[left, right]", "c1"),
	})
	got := commandRuleNames(mustLoadExtends(t, dir, "child").CommandRules)
	if want := []string{"r1", "l1", "rt1", "c1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("command_rules = %v, want %v", got, want)
	}
}

func TestExtendsRejectsRedefiningBaseRuleName(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base":  cmdPolicy("base", "", "shared"),
		"child": cmdPolicy("child", "base", "shared"),
	})
	_, err := loadExtends(t, dir, "child")
	wantErrContains(
		t,
		err,
		`policy "child": command_rules rule "shared" is already defined by base policy "base"`,
	)
}

func TestExtendsChildCannotOverrideBaseDeny(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base": `version: 1
name: base
command_rules:
  - name: deny-rm
    commands: [rm]
    decision: deny
`,
		"child": `version: 1
name: child
extends: base
command_rules:
  - name: allow-rm
    commands: [rm]
    decision: allow
  - name: allow-ls
    commands: [ls]
    decision: allow
`,
	})
	engine, err := NewEngine(mustLoadExtends(t, dir, "child"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if d := engine.CheckCommand(
		"rm",
		[]string{"-rf", "/"},
	); d.PolicyDecision != types.DecisionDeny ||
		d.Rule != "deny-rm" {
		t.Fatalf("rm decision = %s by %q, want deny by deny-rm", d.PolicyDecision, d.Rule)
	}
	if d := engine.CheckCommand(
		"ls",
		nil,
	); d.PolicyDecision != types.DecisionAllow ||
		d.Rule != "allow-ls" {
		t.Fatalf("ls decision = %s by %q, want allow by allow-ls", d.PolicyDecision, d.Rule)
	}
}

func TestExtendsSectionsReplaceOrInherit(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base": `version: 1
name: base
resource_limits:
  pids_max: 10
env_policy:
  allow: [PATH]
audit:
  log_allowed: true
transparent_commands:
  add: [mywrap]
db_services:
  - name: base-db
`,
		"child": `version: 1
name: child
description: child policy
extends: base
env_policy:
  allow: [HOME]
audit:
  log_allowed: false
`,
	})
	p := mustLoadExtends(t, dir, "child")
	if p.ResourceLimits.PidsMax != 10 {
		t.Errorf("resource_limits not inherited: %+v", p.ResourceLimits)
	}
	if !reflect.DeepEqual(p.EnvPolicy.Allow, []string{"HOME"}) {
		t.Errorf("env_policy not replaced: %+v", p.EnvPolicy)
	}
	if p.Audit.LogAllowed {
		t.Errorf("audit set to all-false by child should replace the base section: %+v", p.Audit)
	}
	if p.TransparentCommands == nil ||
		!reflect.DeepEqual(p.TransparentCommands.Add, []string{"mywrap"}) {
		t.Errorf("transparent_commands not inherited: %+v", p.TransparentCommands)
	}
	if p.DBServices.Kind == 0 {
		t.Errorf("db_services not inherited")
	}
	if p.Description != "child policy" {
		t.Errorf("description = %q", p.Description)
	}
}

func TestExtendsMergesMapsAndRejectsKeyConflicts(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base":  "version: 1\nname: base\nenv_inject:\n  A: a\n",
		"child": "version: 1\nname: child\nextends: base\nenv_inject:\n  B: b\n",
		"clash": "version: 1\nname: clash\nextends: base\nenv_inject:\n  A: other\n",
	})
	p := mustLoadExtends(t, dir, "child")
	if want := map[string]string{"A": "a", "B": "b"}; !reflect.DeepEqual(p.EnvInject, want) {
		t.Fatalf("env_inject = %v, want %v", p.EnvInject, want)
	}
	_, err := loadExtends(t, dir, "clash")
	wantErrContains(
		t,
		err,
		`policy "clash": env_inject key "A" is already defined by base policy "base"`,
	)
}

func TestExtendsErrors(t *testing.T) {
	t.Run("missing base", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{"x": cmdPolicy("x", "base", "x1")})
		_, err := loadExtends(t, dir, "x")
		wantErrContains(t, err, `policy "x" extends "base": policy "base" not found in "`+dir+`"`)
	})
	t.Run("invalid name", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{"x": cmdPolicy("x", "../etc", "x1")})
		_, err := loadExtends(t, dir, "x")
		wantErrContains(t, err, `policy "x" extends "../etc": invalid policy name`)
	})
	t.Run("cycle", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{
			"a": cmdPolicy("a", "b", "a1"),
			"b": cmdPolicy("b", "a", "b1"),
		})
		_, err := loadExtends(t, dir, "a")
		wantErrContains(t, err, "policy extends cycle: a -> b -> a")
	})
	t.Run("self", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{"a": cmdPolicy("a", "a", "a1")})
		_, err := loadExtends(t, dir, "a")
		wantErrContains(t, err, "policy extends cycle: a -> a")
	})
	t.Run("depth", func(t *testing.T) {
		files := map[string]string{}
		// p0 extends p1 ... extends p<n>: maxExtendsDepth hops are allowed.
		for i := 0; i <= maxExtendsDepth+1; i++ {
			name := "p" + string(rune('a'+i))
			extends := ""
			if i <= maxExtendsDepth {
				extends = "p" + string(rune('a'+i+1))
			}
			files[name] = cmdPolicy(name, extends, name+"-rule")
		}
		dir := writePolicies(t, files)
		_, err := loadExtends(t, dir, "pa")
		wantErrContains(t, err, "policy extends depth exceeds 8")
		if _, err := loadExtends(t, dir, "pb"); err != nil {
			t.Fatalf("chain of exactly %d hops: %v", maxExtendsDepth, err)
		}
	})
	t.Run("base parse error", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{
			"base":  "version: 1\nname: base\nbogus: true\n",
			"child": cmdPolicy("child", "base", "c1"),
		})
		_, err := loadExtends(t, dir, "child")
		wantErrContains(t, err, `policy "child" extends "base": parse policy:`)
	})
	t.Run("load from bytes", func(t *testing.T) {
		_, err := LoadFromBytes([]byte(cmdPolicy("child", "base", "c1")))
		wantErrContains(
			t,
			err,
			"base policies can only be resolved when the policy is loaded from a policy directory",
		)
	})
	t.Run("merged policy validated", func(t *testing.T) {
		dir := writePolicies(t, map[string]string{
			"base": "version: 1\nname: base\nfile_rules:\n  - name: b\n" +
				"    project_overlay_boundary: true\n    paths: ['**']\n" +
				"    operations: ['*']\n    decision: deny\n",
			"child": "version: 1\nname: child\nextends: base\n" +
				"resource_limits:\n  command_timeout: 1ns\n",
		})
		_, err := loadExtends(t, dir, "child")
		wantErrContains(t, err, "validate policy: positive resource_limits.command_timeout")
	})
}

func TestExtendsReadCallbackUsedForEveryFile(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"root":  cmdPolicy("root", "", "r1"),
		"base":  cmdPolicy("base", "root", "b1"),
		"child": cmdPolicy("child", "base", "c1"),
	})
	var read []string
	_, err := LoadFile(filepath.Join(dir, "child.yaml"), func(path string) ([]byte, error) {
		read = append(read, filepath.Base(path))
		return os.ReadFile(path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"child.yaml", "base.yaml", "root.yaml"}; !reflect.DeepEqual(read, want) {
		t.Fatalf("read = %v, want %v", read, want)
	}
}

func TestManagerVerifiesBaseSignature(t *testing.T) {
	dir, tsDir := setupSignedPolicyDir(t, "child", cmdPolicy("child", "base", "c1"))
	writePolicy(t, dir, "base.yaml", cmdPolicy("base", "", "b1"))

	m := NewManager(dir, "child", []string{"child"}, "", "child")
	m.SetSigningConfig("enforce", tsDir)
	_, err := m.Get()
	wantErrContains(t, err, `policy "child" extends "base": signing verification:`)
}

func TestManagerAcceptsSignedBase(t *testing.T) {
	dir, tsDir := setupSignedPolicyDir(t, "child", cmdPolicy("child", "base", "c1"))
	writePolicy(t, dir, "base.yaml", cmdPolicy("base", "", "b1"))
	keyDir := t.TempDir()
	if _, err := signing.GenerateKeypair(keyDir, "base"); err != nil {
		t.Fatal(err)
	}
	if err := signing.SignFile(
		filepath.Join(dir, "base.yaml"),
		filepath.Join(keyDir, "private.key.json"),
		"",
		"",
	); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	writePolicy(t, tsDir, "base-key.json", string(pub))

	m := NewManager(dir, "child", []string{"child"}, "", "child")
	m.SetSigningConfig("enforce", tsDir)
	p, err := m.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got := commandRuleNames(p.CommandRules); !reflect.DeepEqual(got, []string{"b1", "c1"}) {
		t.Fatalf("command_rules = %v", got)
	}
}

func TestManagerVerifiesBaseManifestHash(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base":  cmdPolicy("base", "", "b1"),
		"child": cmdPolicy("child", "base", "c1"),
	})
	manifest := filepath.Join(t.TempDir(), "manifest")
	writePolicy(
		t,
		filepath.Dir(manifest),
		"manifest",
		hashFile(t, filepath.Join(dir, "child.yaml"))+"  child.yaml\n",
	)
	m := NewManager(dir, "child", []string{"child"}, manifest, "child")
	_, err := m.Get()
	wantErrContains(
		t,
		err,
		`policy "child" extends "base": policy not listed in manifest: base.yaml`,
	)
}

func TestExtendsOverlayRulesFollowInheritedRules(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		// The base marks a boundary and ends with a terminal deny; both only
		// apply when the base is used directly.
		"base": `version: 1
name: base
file_rules:
  - name: base-allow
    paths: [/base/**]
    operations: [read]
    decision: allow
  - name: base-boundary
    project_overlay_boundary: true
    paths: [/secret/**]
    operations: ['*']
    decision: deny
  - name: default-deny-base
    paths: ['**']
    operations: ['*']
    decision: deny
command_rules:
  - name: base-cmd
    project_overlay_boundary: true
    commands: [rm]
    decision: deny
`,
		"child": `version: 1
name: child
extends: base
file_rules:
  - name: child-allow
    paths: [/child/**]
    operations: [read]
    decision: allow
  - name: default-deny-child
    paths: ['**']
    operations: ['*']
    decision: deny
`,
	})
	overlay := PolicyOverlay{
		Name: "proj",
		FileRules: []FileRule{
			{
				Name:       "overlay-file",
				Paths:      []string{"/secret/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
		},
		CommandRules: []CommandRule{
			{Name: "overlay-cmd", Commands: []string{"rm"}, Decision: "allow"},
		},
	}

	base := mustLoadExtends(t, dir, "base")
	direct, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fileRuleNames(
		direct.FileRules,
	), []string{
		"base-allow",
		"overlay-file",
		"base-boundary",
		"default-deny-base",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("direct base file_rules = %v, want %v", got, want)
	}

	child := mustLoadExtends(t, dir, "child")
	for _, r := range child.FileRules {
		if r.ProjectOverlayBoundary {
			t.Fatalf("inherited rule %q kept project_overlay_boundary", r.Name)
		}
	}
	merged, err := MergePolicyOverlays(child, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fileRuleNames(
		merged.FileRules,
	), []string{
		"base-allow",
		"base-boundary",
		"default-deny-base",
		"child-allow",
		"overlay-file",
		"default-deny-child",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("extended file_rules = %v, want %v", got, want)
	}
	if got, want := commandRuleNames(
		merged.CommandRules,
	), []string{
		"base-cmd",
		"overlay-cmd",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("extended command_rules = %v, want %v", got, want)
	}

	engine, err := NewEngine(merged, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if d := engine.CheckFile("/secret/key", "read"); d.PolicyDecision != types.DecisionDeny {
		t.Fatalf("/secret/key read = %s by %q, want deny from the base", d.PolicyDecision, d.Rule)
	}
}

func TestExtendsHashCoversResolvedPolicy(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"base":  cmdPolicy("base", "", "b1"),
		"child": cmdPolicy("child", "base", "c1"),
	})
	before, err := HashEffectivePolicy(mustLoadExtends(t, dir, "child"))
	if err != nil {
		t.Fatal(err)
	}
	writePolicy(t, dir, "base.yaml", cmdPolicy("base", "", "b2"))
	after, err := HashEffectivePolicy(mustLoadExtends(t, dir, "child"))
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("effective policy hash did not change when the base changed")
	}
}
