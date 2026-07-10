package nethelper

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterSessionCgroupRequestJSONRoundTripDefaults(t *testing.T) {
	req := RegisterSessionCgroupRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "req-1",
		SessionID:       "session-1",
		CgroupPath:      filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1"),
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if req.Mode.Normalized() != BuiltinModeCgroupConnectGate {
		t.Fatalf("default mode = %q", req.Mode.Normalized())
	}
	if req.Tier.Normalized() != EnforcementTierNone {
		t.Fatalf("default tier = %q", req.Tier.Normalized())
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(b)
	for _, omitted := range []string{"mode", "tier", "proxy", "pin_path", "session_nonce"} {
		if strings.Contains(wire, omitted) {
			t.Fatalf("omitempty field %q unexpectedly present in %s", omitted, wire)
		}
	}

	got, err := DecodeRegisterSessionCgroupRequestJSON(b)
	if err != nil {
		t.Fatalf("DecodeRegisterSessionCgroupRequestJSON: %v", err)
	}
	if got.SessionID != req.SessionID || got.CgroupPath != req.CgroupPath {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, req)
	}
	if got.Mode.Normalized() != BuiltinModeCgroupConnectGate {
		t.Fatalf("decoded default mode = %q", got.Mode.Normalized())
	}
}

func TestUpdatePolicyMapRequestJSONRoundTripDefaults(t *testing.T) {
	req := UpdatePolicyMapRequest{
		ProtocolVersion: CurrentProtocolVersion,
		SessionID:       "session-1",
		CgroupID:        42,
		DefaultDeny:     true,
		Allow: []PolicyMapEntry{
			{IP: "127.0.0.1", Port: 8080},
		},
		Deny: []PolicyMapEntry{
			{CIDR: "169.254.169.254/32", Protocol: TransportProtocolTCP},
		},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if req.Allow[0].Protocol.Normalized() != TransportProtocolAny {
		t.Fatalf("default protocol = %q", req.Allow[0].Protocol.Normalized())
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(b)
	if strings.Contains(wire, "proxy") || strings.Contains(wire, "family") {
		t.Fatalf("omitempty fields unexpectedly present in %s", wire)
	}

	got, err := DecodeUpdatePolicyMapRequestJSON(b)
	if err != nil {
		t.Fatalf("DecodeUpdatePolicyMapRequestJSON: %v", err)
	}
	if !got.DefaultDeny || len(got.Allow) != 1 || len(got.Deny) != 1 {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
	if got.Allow[0].Protocol.Normalized() != TransportProtocolAny {
		t.Fatalf("decoded default protocol = %q", got.Allow[0].Protocol.Normalized())
	}
}

func TestResponseJSONOmitsOptionalDefaults(t *testing.T) {
	resp := RegisterSessionCgroupResponse{
		ProtocolVersion:       CurrentProtocolVersion,
		RequestID:             "req-1",
		SessionID:             "session-1",
		OK:                    true,
		Tier:                  EnforcementTierHelperEBPFProxy,
		Mode:                  BuiltinModeCgroupProxyRedirect,
		CgroupID:              42,
		NetworkPolicyEnforced: true,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(b)
	for _, omitted := range []string{"warnings", "error", "pin_path"} {
		if strings.Contains(wire, omitted) {
			t.Fatalf("omitempty field %q unexpectedly present in %s", omitted, wire)
		}
	}

	var got RegisterSessionCgroupResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !got.OK || !got.NetworkPolicyEnforced || got.CgroupID != 42 {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
}

func TestStrictDecodeRejectsDangerousUnknownFields(t *testing.T) {
	basePath := filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1")
	cases := []struct {
		name   string
		body   map[string]any
		update bool
	}{
		{
			name: "bpf bytecode",
			body: map[string]any{
				"protocol_version": CurrentProtocolVersion,
				"session_id":       "session-1",
				"cgroup_path":      basePath,
				"bpf_bytecode":     "AAAA",
			},
		},
		{
			name: "program fd",
			body: map[string]any{
				"protocol_version": CurrentProtocolVersion,
				"session_id":       "session-1",
				"cgroup_path":      basePath,
				"program_fd":       7,
			},
		},
		{
			name: "map fd on update",
			body: map[string]any{
				"protocol_version": CurrentProtocolVersion,
				"session_id":       "session-1",
				"cgroup_id":        42,
				"default_deny":     true,
				"map_fd":           8,
			},
			update: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if strings.Contains(string(payload), string(rune(0))) {
				t.Fatal("test JSON contains NUL")
			}
			if tc.update {
				_, err = DecodeUpdatePolicyMapRequestJSON(payload)
			} else {
				_, err = DecodeRegisterSessionCgroupRequestJSON(payload)
			}
			if err == nil {
				t.Fatal("expected strict decode error")
			}
		})
	}
}

func TestValidateRejectsDangerousOrInvalidRequests(t *testing.T) {
	cgroupPath := filepath.Join("sys", "fs", "cgroup", "agentsh", "session-1")
	traversalPath := filepath.Join("agentsh", "..", "..", "root")
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "invalid built in mode",
			err:  RegisterSessionCgroupRequest{SessionID: "session-1", CgroupPath: cgroupPath, Mode: BuiltinMode("load-bpf-object")}.Validate(),
		},
		{
			name: "helper proxy tier requires proxy metadata",
			err:  RegisterSessionCgroupRequest{SessionID: "session-1", CgroupPath: cgroupPath, Tier: EnforcementTierHelperEBPFProxy}.Validate(),
		},
		{
			name: "proxy redirect requires loopback proxy",
			err:  RegisterSessionCgroupRequest{SessionID: "session-1", CgroupPath: cgroupPath, Mode: BuiltinModeCgroupProxyRedirect, Proxy: &ProxyEndpoint{Host: "example.com", Port: 8080}}.Validate(),
		},
		{
			name: "negative supervisor pid",
			err:  RegisterSessionCgroupRequest{SessionID: "session-1", CgroupPath: cgroupPath, SupervisorPID: -1}.Validate(),
		},
		{
			name: "update requires cgroup target",
			err:  UpdatePolicyMapRequest{SessionID: "session-1", DefaultDeny: true}.Validate(),
		},
		{
			name: "invalid protocol",
			err:  UpdatePolicyMapRequest{SessionID: "session-1", CgroupID: 42, Allow: []PolicyMapEntry{{IP: "127.0.0.1", Protocol: TransportProtocol("icmp")}}}.Validate(),
		},
		{
			name: "family mismatch",
			err:  UpdatePolicyMapRequest{SessionID: "session-1", CgroupID: 42, Allow: []PolicyMapEntry{{IP: "127.0.0.1", Family: IPFamilyIPv6}}}.Validate(),
		},
		{
			name: "unspecified ip",
			err:  UpdatePolicyMapRequest{SessionID: "session-1", CgroupID: 42, Allow: []PolicyMapEntry{{IP: "0.0.0.0"}}}.Validate(),
		},
		{
			name: "cleanup path traversal",
			err:  CleanupSessionRequest{SessionID: "session-1", CgroupPath: traversalPath}.Validate(),
		},
		{
			name: "future protocol version",
			err:  CleanupSessionRequest{ProtocolVersion: CurrentProtocolVersion + 1, SessionID: "session-1"}.Validate(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestReleaseInstanceRequestStrictValidation(t *testing.T) {
	req := ReleaseInstanceRequest{
		ProtocolVersion:          CurrentProtocolVersion,
		RequestID:                "release-1",
		LeaseID:                  "lease-11111111-1111-4111-8111-111111111111",
		HelperInstanceCredential: "0123456789abcdef0123456789abcdef",
	}
	wire, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeReleaseInstanceRequestJSON(wire)
	if err != nil {
		t.Fatalf("DecodeReleaseInstanceRequestJSON: %v", err)
	}
	if got.LeaseID != req.LeaseID || got.HelperInstanceCredential != req.HelperInstanceCredential {
		t.Fatalf("round trip mismatch: got %+v", got)
	}
	for _, invalid := range []string{
		`{"lease_id":"lease-1","helper_instance_credential":""}`,
		`{"lease_id":"lease-1","helper_instance_credential":"abc","unit":"root.service"}`,
		`{"lease_id":"lease-1","helper_instance_credential":"abc","pin_root":"/sys/fs/bpf"}`,
	} {
		if _, err := DecodeReleaseInstanceRequestJSON([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid release request: %s", invalid)
		}
	}
}

func TestCleanupSessionRequestJSONRoundTripDefaults(t *testing.T) {
	req := CleanupSessionRequest{
		ProtocolVersion: CurrentProtocolVersion,
		RequestID:       "req-1",
		SessionID:       "session-1",
		Reason:          CleanupReasonSessionEnded,
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire := string(b)
	if strings.Contains(wire, "cgroup_id") || strings.Contains(wire, "pin_path") {
		t.Fatalf("omitempty fields unexpectedly present in %s", wire)
	}
	got, err := DecodeCleanupSessionRequestJSON(b)
	if err != nil {
		t.Fatalf("DecodeCleanupSessionRequestJSON: %v", err)
	}
	if got.SessionID != req.SessionID || got.Reason != req.Reason {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, req)
	}
}
