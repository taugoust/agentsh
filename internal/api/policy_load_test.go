package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy/signing"
)

func TestDefaultPolicyLoaderVerifiesExtendedBaseSignature(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(
		"base.yaml",
		"version: 1\nname: base\ncommand_rules:\n"+
			"  - name: deny-rm\n    commands: [rm]\n    decision: deny\n",
	)
	write(
		"child.yaml",
		"version: 1\nname: child\nextends: base\ncommand_rules:\n"+
			"  - name: allow-ls\n    commands: [ls]\n    decision: allow\n",
	)

	keyDir := t.TempDir()
	if _, err := signing.GenerateKeypair(keyDir, "test"); err != nil {
		t.Fatal(err)
	}
	sign := func(name string) {
		t.Helper()
		if err := signing.SignFile(
			filepath.Join(dir, name),
			filepath.Join(keyDir, "private.key.json"),
			"",
			"",
		); err != nil {
			t.Fatal(err)
		}
	}
	trustStore := t.TempDir()
	pub, err := os.ReadFile(filepath.Join(keyDir, "public.key.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustStore, "key.json"), pub, 0o644); err != nil {
		t.Fatal(err)
	}

	sign("child.yaml")
	loader := NewDefaultPolicyLoader(dir, false, true, "enforce", trustStore)
	_, err = loader.Load("child")
	var sigErr *policySigningError
	if !errors.As(err, &sigErr) || sigErr.status != http.StatusForbidden ||
		!strings.Contains(err.Error(), `policy "child" extends "base": policy signing:`) {
		t.Fatalf("unsigned base: err = %v, want a forbidden signing error for the base", err)
	}

	sign("base.yaml")
	engine, err := loader.Load("child")
	if err != nil {
		t.Fatalf("signed base: %v", err)
	}
	if got := engine.Policy().CommandRules; len(got) != 2 || got[0].Name != "deny-rm" ||
		got[1].Name != "allow-ls" {
		t.Fatalf("command rules = %+v, want base rule first", got)
	}
}
