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

func TestBuildProxyOnlyAllowedEndpoints_ExactTCPListeners(t *testing.T) {
	entries, cidrs, err := buildProxyOnlyAllowedEndpoints("http://127.0.0.1:18081", "http://[::1]:19091")
	if err != nil {
		t.Fatalf("build exact proxy endpoints: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected two exact proxy entries, got %d", len(entries))
	}
	if len(cidrs) != 0 {
		t.Fatalf("proxy-required mode must not contain broad loopback CIDRs: %+v", cidrs)
	}
	seen4 := false
	seen6 := false
	for _, entry := range entries {
		if entry.Protocol != 6 {
			t.Fatalf("proxy endpoint protocol = %d, want TCP", entry.Protocol)
		}
		switch {
		case entry.Family == 2 && entry.Dport == 18081 && net.IP(entry.Addr[:4]).Equal(net.ParseIP("127.0.0.1")):
			seen4 = true
		case entry.Family == 10 && entry.Dport == 19091 && net.IP(entry.Addr[:]).Equal(net.ParseIP("::1")):
			seen6 = true
		}
		if entry.Family == 2 && net.IP(entry.Addr[:4]).Equal(net.ParseIP("1.0.0.127")) {
			t.Fatal("byte-swapped 1.0.0.127 workaround must not be present")
		}
	}
	if !seen4 || !seen6 {
		t.Fatalf("expected exact IPv4 and IPv6 proxy listeners, entries=%+v", entries)
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
