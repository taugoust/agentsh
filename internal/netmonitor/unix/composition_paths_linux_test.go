//go:build linux && cgo

package unix

import (
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/composition"
)

func TestCompositionPathRegistryOwnerHelper(t *testing.T) {
	if os.Getenv("AGENTSH_TEST_COMPOSITION_PATH_OWNER") != "1" {
		return
	}
	barrier := os.NewFile(3, "composition-path-owner-barrier")
	if barrier == nil {
		t.Fatal("owner barrier is unavailable")
	}
	defer barrier.Close()
	_, _ = io.Copy(io.Discard, barrier)
}

func TestCompositionPathRegistryRemovesMappingAfterPinnedOwnerExit(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	barrierRead, barrierWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	owner := exec.Command(self, "-test.run=^TestCompositionPathRegistryOwnerHelper$")
	owner.Env = append(os.Environ(), "AGENTSH_TEST_COMPOSITION_PATH_OWNER=1")
	owner.ExtraFiles = []*os.File{barrierRead}
	if err := owner.Start(); err != nil {
		barrierRead.Close()
		barrierWrite.Close()
		t.Fatal(err)
	}
	barrierRead.Close()
	t.Cleanup(func() {
		_ = barrierWrite.Close()
		if owner.ProcessState == nil {
			_ = owner.Process.Kill()
			_ = owner.Wait()
		}
	})

	registry := NewCompositionPathRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	if err := registry.Register(os.Getpid(), owner.Process.Pid, composition.PathMappings{Aliases: []composition.PathAlias{
		{Target: "/", Source: ""},
		{Target: "/visible", Source: "/source"},
	}}); err != nil {
		_ = owner.Process.Kill()
		_ = owner.Wait()
		t.Fatal(err)
	}
	if got, covered, err := registry.Resolve(os.Getpid(), "/visible/file"); err != nil || !covered || got != "/source/file" {
		t.Fatalf("mapping before owner exit = %q covered=%v err=%v", got, covered, err)
	}
	if err := barrierWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		got, covered, err := registry.Resolve(os.Getpid(), "/visible/file")
		if err != nil {
			t.Fatal(err)
		}
		if !covered && got == "/visible/file" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mapping remained after owner exit: %q covered=%v", got, covered)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCompositionPathRegistryStaleOwnerCannotRemoveReplacementSnapshot(t *testing.T) {
	registry := NewCompositionPathRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	pid := os.Getpid()
	for _, source := range []string{"/source-a", "/source-b"} {
		if err := registry.Register(pid, pid, composition.PathMappings{Aliases: []composition.PathAlias{
			{Target: "/", Source: ""},
			{Target: "/visible", Source: source},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	got, covered, err := registry.Resolve(pid, "/visible/file")
	if err != nil || !covered || got != "/source-b/file" {
		t.Fatalf("replacement mapping = %q covered=%v err=%v", got, covered, err)
	}
}

func TestCompositionPathRegistryResolvesAliasesFreshBarriersSymlinksAndNesting(t *testing.T) {
	registry := NewCompositionPathRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	pid := os.Getpid()
	if err := registry.Register(pid, pid, composition.PathMappings{
		Aliases: []composition.PathAlias{
			{Target: "/", Source: ""},
			{Target: "/alias", Source: "/source"},
			{Target: "/alias/fresh", Source: ""},
		},
		Symlinks: []composition.PathSymlink{
			{Target: "/link", Source: "/alias/file"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "/alias/child", want: "/source/child"},
		{path: "/alias/fresh/child", want: "/alias/fresh/child"},
		{path: "/link", want: "/source/file"},
	} {
		got, covered, err := registry.Resolve(pid, test.path)
		if err != nil || !covered || got != test.want {
			t.Errorf("Resolve(%q) = %q covered=%v err=%v, want %q", test.path, got, covered, err, test.want)
		}
	}

	// Registration normalizes a nested plan's source through the parent's
	// already-published alias snapshot before replacing the same test namespace.
	if err := registry.Register(pid, pid, composition.PathMappings{
		Aliases: []composition.PathAlias{
			{Target: "/", Source: ""},
			{Target: "/inner", Source: "/alias/subtree"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	got, covered, err := registry.Resolve(pid, "/inner/file")
	if err != nil || !covered || got != "/source/subtree/file" {
		t.Fatalf("nested Resolve = %q covered=%v err=%v", got, covered, err)
	}
}
