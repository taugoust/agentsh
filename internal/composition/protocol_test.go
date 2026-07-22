package composition

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeNamespaceMapRequestBindsNonceAndRejectsUnknownFields(t *testing.T) {
	const nonce = "00112233445566778899aabbccddeeff"
	payload := []byte(`{"version":1,"type":"namespace-map","uid":1,"gid":1,"nonce":"` + nonce + `"}`)
	request, err := decodeNamespaceMapRequest(payload, nonce)
	if err != nil || request.Nonce != nonce {
		t.Fatalf("request=%+v err=%v", request, err)
	}
	for name, malformed := range map[string]string{
		"replayed nonce":  strings.Replace(string(payload), nonce, strings.Repeat("f", 32), 1),
		"unknown field":   strings.TrimSuffix(string(payload), "}") + `,"extra":true}`,
		"duplicate field": strings.TrimSuffix(string(payload), "}") + `,"uid":1}`,
		"trailing value":  string(payload) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeNamespaceMapRequest([]byte(malformed), nonce); err == nil {
				t.Fatal("expected fail-closed decode")
			}
		})
	}
}

func TestDecodePlanRequestRejectsNonceReplayDuplicateAndUnknownFields(t *testing.T) {
	const nonce = "00112233445566778899aabbccddeeff"
	plan := Plan{
		Version: ProtocolVersion,
		Dialect: Dialect,
		Nonce:   nonce,
		Cwd:     "/",
		Command: []string{"/bin/true"},
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePlanRequest(payload, nonce, 4); err != nil {
		t.Fatal(err)
	}

	wrongNonce := plan
	wrongNonce.Nonce = strings.Repeat("f", 32)
	wrongPayload, _ := json.Marshal(wrongNonce)
	_, err = decodePlanRequest(wrongPayload, nonce, 4)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != "E_COMPOSITION_REQUESTER_CHANGED" {
		t.Fatalf("nonce error = %v", err)
	}

	for name, malformed := range map[string]string{
		"unknown field":   strings.TrimSuffix(string(payload), "}") + `,"extra":true}`,
		"duplicate field": strings.TrimSuffix(string(payload), "}") + `,"dialect":"0.11.2"}`,
		"trailing value":  string(payload) + `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePlanRequest([]byte(malformed), nonce, 4); err == nil {
				t.Fatal("expected fail-closed decode")
			}
		})
	}
}

func TestParseSourceMountInventoryRejectsMalformedAndEscapingRecords(t *testing.T) {
	valid := []byte("S\t1\t0\text4\t/source\nM\t2\t15\ttmpfs\t/source/child\n")
	mounts, err := parseSourceMountInventory(valid, "/source")
	if err != nil || len(mounts) != 2 {
		t.Fatalf("mounts=%v err=%v", mounts, err)
	}
	for _, malformed := range [][]byte{
		[]byte("S\t1\t0\text4\t/source\nM\t2\t0\ttmpfs\t/outside\n"),
		[]byte("S\t1\t0\text4\t/source\nM\t1\t0\ttmpfs\t/source/child\n"),
		[]byte("M\t2\t0\ttmpfs\t/source/child\n"),
	} {
		if _, err := parseSourceMountInventory(malformed, "/source"); err == nil {
			t.Fatalf("accepted malformed inventory %q", malformed)
		}
	}
}
