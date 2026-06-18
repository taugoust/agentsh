package api

import (
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestBuildAllowedEndpoints_StrictExactDomain(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(_ string, _ time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("1.1.1.1")}, 30 * time.Second
	}
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-google",
				Domains:  []string{"www.google.com"},
				Ports:    []int{443},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	entries, cidrs, deny, denyCIDRs, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if !strict {
		t.Fatalf("expected strict enforcement when only exact domains are present")
	}
	if len(entries) == 0 && len(cidrs) == 0 {
		t.Fatalf("expected entries for resolved domain")
	}
	if len(deny) != 0 || len(denyCIDRs) != 0 {
		t.Fatalf("expected no deny entries")
	}
}

func TestBuildAllowedEndpoints_NonStrictOnWildcard(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	resolveDomainWithTTL = func(_ string, _ time.Duration) ([]net.IP, time.Duration) {
		return []net.IP{net.ParseIP("1.1.1.1")}, 30 * time.Second
	}
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-wild",
				Domains:  []string{"*.example.com"},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if strict {
		t.Fatalf("wildcard domains should disable strict/default-deny")
	}
}

func TestBuildProxyOnlyAllowedEndpoints_LoopbackOnly(t *testing.T) {
	entries, cidrs := buildProxyOnlyAllowedEndpoints("http://127.0.0.1:18081", "http://127.0.0.1:19091")
	if len(entries) != 0 {
		t.Fatalf("expected no exact entries for proxy-only mode, got %d", len(entries))
	}
	if len(cidrs) != 3 {
		t.Fatalf("expected IPv4 network-order, IPv4 native-order, and IPv6 loopback CIDRs, got %d", len(cidrs))
	}
	seen4 := false
	seen6 := false
	for _, c := range cidrs {
		if c.Dport != 0 {
			t.Fatalf("proxy-only loopback CIDR should allow any loopback port, got dport=%d", c.Dport)
		}
		if c.Family == 2 && c.PrefixLen == 32 && net.IP(c.Addr[:4]).Equal(net.ParseIP("127.0.0.1")) {
			seen4 = true
		}
		if c.Family == 10 && c.PrefixLen == 128 && net.IP(c.Addr[:]).Equal(net.ParseIP("::1")) {
			seen6 = true
		}
	}
	if !seen4 || !seen6 {
		t.Fatalf("expected loopback v4/v6 CIDRs, seen4=%v seen6=%v cidrs=%+v", seen4, seen6, cidrs)
	}
}

func TestBuildAllowedEndpoints_NonStrictOnCIDR(t *testing.T) {
	t.Cleanup(func() { resolveDomainWithTTL = resolveDomainTTL })
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-cidr",
				CIDRs:    []string{"10.0.0.0/8"},
				Decision: "allow",
			},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	_, cidrs, _, _, strict, _, _ := buildAllowedEndpoints(engine, 60*time.Second)
	if !strict {
		t.Fatalf("CIDR rules should allow strict/default-deny now that LPM is used")
	}
	if len(cidrs) == 0 {
		t.Fatalf("expected cidr to be included")
	}
}
