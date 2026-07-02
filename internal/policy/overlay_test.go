package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverProjectOverlaysDisabled(t *testing.T) {
	root := t.TempDir()
	writeOverlay(t, root, "xilinx.yaml", "name: xilinx\nfile_rules:\n  - name: allow-xilinx\n    paths: [/share/xilinx/**]\n    operations: [read]\n    decision: allow\n")
	files, err := DiscoverProjectOverlays(root, ProjectOverlaysConfig{Enabled: false})
	if err != nil {
		t.Fatalf("DiscoverProjectOverlays: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("disabled discovery returned %d overlays", len(files))
	}
}

func TestDiscoverProjectOverlaysValidation(t *testing.T) {
	root := t.TempDir()
	for _, pattern := range []string{"/tmp/*.yaml", "../*.yaml"} {
		_, err := DiscoverProjectOverlays(root, ProjectOverlaysConfig{Enabled: true, Paths: []string{pattern}})
		if err == nil {
			t.Fatalf("pattern %q: expected error", pattern)
		}
	}
}

func TestLoadOverlayKnownFieldsAndDuplicates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bad.yaml")
	if err := os.WriteFile(path, []byte("name: bad\nversion: 1\nfile_rules:\n  - name: dup\n    paths: [/**]\n    operations: [read]\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "field version not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}

	path = filepath.Join(root, "dup.yaml")
	if err := os.WriteFile(path, []byte("name: dup\nfile_rules:\n  - name: same\n    paths: [/a]\n    operations: [read]\n    decision: allow\ncommand_rules:\n  - name: same\n    commands: [echo]\n    decision: allow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOverlay(path); err == nil || !strings.Contains(err.Error(), "duplicate overlay rule name") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestMergePolicyOverlaysOrdering(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		FileRules: []FileRule{
			{Name: "deny-secrets", Paths: []string{"/secret/**"}, Operations: []string{"read"}, Decision: "deny"},
			{Name: "default-deny-files", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"},
		},
		CommandRules: []CommandRule{
			{Name: "default-deny-commands", Decision: "deny"},
		},
	}
	overlay := PolicyOverlay{
		Name:         "xilinx",
		FileRules:    []FileRule{{Name: "allow-xilinx-read-exec", Paths: []string{"/share/xilinx", "/share/xilinx/**"}, Operations: []string{"read", "open", "stat", "list", "readlink", "execute"}, Decision: "allow"}},
		CommandRules: []CommandRule{{Name: "allow-xsc", Commands: []string{"xsc", "/share/xilinx/**"}, Decision: "allow"}},
	}
	merged, err := MergePolicyOverlays(base, []PolicyOverlay{overlay})
	if err != nil {
		t.Fatalf("MergePolicyOverlays: %v", err)
	}
	gotFile := []string{merged.FileRules[0].Name, merged.FileRules[1].Name, merged.FileRules[2].Name}
	wantFile := []string{"deny-secrets", "allow-xilinx-read-exec", "default-deny-files"}
	for i := range wantFile {
		if gotFile[i] != wantFile[i] {
			t.Fatalf("file rule order = %v, want %v", gotFile, wantFile)
		}
	}
	gotCmd := []string{merged.CommandRules[0].Name, merged.CommandRules[1].Name}
	wantCmd := []string{"allow-xsc", "default-deny-commands"}
	for i := range wantCmd {
		if gotCmd[i] != wantCmd[i] {
			t.Fatalf("command rule order = %v, want %v", gotCmd, wantCmd)
		}
	}
}

func TestMergePolicyOverlaysRejectsBaseNameConflict(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", FileRules: []FileRule{{Name: "same", Paths: []string{"**"}, Operations: []string{"*"}, Decision: "deny"}}}
	overlay := PolicyOverlay{Name: "o", FileRules: []FileRule{{Name: "same", Paths: []string{"/x"}, Operations: []string{"read"}, Decision: "allow"}}}
	if _, err := MergePolicyOverlays(base, []PolicyOverlay{overlay}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func writeOverlay(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".agentsh", "policy-overlays")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
