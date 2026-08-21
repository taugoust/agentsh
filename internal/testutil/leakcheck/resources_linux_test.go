//go:build linux

package leakcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestResourceSnapshotDetectsOpenFile(t *testing.T) {
	if err := prepareResourceTracking(); err != nil {
		t.Fatal(err)
	}
	baseline, err := snapshotResources()
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "open-file")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	current, err := snapshotResources()
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if want := "file descriptor: " + name; !slices.Contains(diffResources(baseline, current), want) {
		file.Close()
		t.Fatalf("open descriptor %q was not detected", want)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if leaked, err := waitForResourceCleanup(baseline, time.Second); err != nil || len(leaked) != 0 {
		t.Fatalf("resources after close = %v, err = %v", leaked, err)
	}
}

func TestResourceSnapshotDetectsChildProcess(t *testing.T) {
	if os.Getenv("AGENTSH_LEAKCHECK_CHILD") == "1" {
		select {}
	}
	if err := prepareResourceTracking(); err != nil {
		t.Fatal(err)
	}
	baseline, err := snapshotResources()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=TestResourceSnapshotDetectsChildProcess")
	command.Env = append(os.Environ(), "AGENTSH_LEAKCHECK_CHILD=1")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})

	current, err := snapshotResources()
	if err != nil {
		t.Fatal(err)
	}
	want := "child process: pid " + strconv.Itoa(command.Process.Pid)
	if !slices.Contains(diffResources(baseline, current), want) {
		t.Fatalf("running child %q was not detected", want)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("killed child unexpectedly exited successfully")
	}
	reaped = true
	if leaked, err := waitForResourceCleanup(baseline, time.Second); err != nil || len(leaked) != 0 {
		t.Fatalf("resources after child reap = %v, err = %v", leaked, err)
	}
}
