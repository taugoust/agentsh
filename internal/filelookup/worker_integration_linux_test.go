//go:build linux

package filelookup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeLookupWorkerClassifiesExistingAndAbsent(t *testing.T) {
	workerPath := os.Getenv("AGENTSH_FILE_LOOKUP_WORKER_TEST")
	if workerPath == "" {
		t.Skip("native worker path is supplied by the focused Nix check")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "exists"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path  string
		class Class
		errno int32
	}{{"exists", ClassExists, 0}, {"missing", ClassAbsent, int32(unix.ENOENT)}} {
		t.Run(test.path, func(t *testing.T) {
			result := runNativeWorker(t, workerPath, directory, test.path)
			if result.Class != test.class || result.Errno != test.errno {
				t.Fatalf("result = %+v, want class=%d errno=%d", result, test.class, test.errno)
			}
		})
	}
}

func TestNativeLookupWorkerDistinguishesLookupFailuresAndSymlinks(t *testing.T) {
	workerPath := os.Getenv("AGENTSH_FILE_LOOKUP_WORKER_TEST")
	if workerPath == "" {
		t.Skip("native worker path is supplied by the focused Nix check")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "regular"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(directory, "dangling")); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(directory, "blocked")
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o700) })

	tests := []struct {
		name      string
		path      string
		operation Operation
		class     Class
		reason    Reason
	}{
		{"inaccessible parent is not absent", "blocked/missing", OperationOpen, ClassInaccessible, ReasonErrno},
		{"non-directory ancestor is distinct", "regular/child", OperationOpen, ClassNotDirectory, ReasonErrno},
		{"dangling followed symlink is conservative", "dangling", OperationOpen, ClassUnknown, ReasonSymlinkContext},
		{"readlink metadata sees dangling symlink", "dangling", OperationReadlinkMetadata, ClassExists, ReasonNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runNativeWorkerOperation(t, workerPath, directory, test.path, test.operation)
			if result.Class != test.class || result.Reason != test.reason {
				t.Fatalf("result = %+v, want class=%d reason=%d", result, test.class, test.reason)
			}
		})
	}
}

func runNativeWorker(t *testing.T, workerPath, directory, path string) Result {
	return runNativeWorkerOperation(t, workerPath, directory, path, OperationOpen)
}

func runNativeWorkerOperation(t *testing.T, workerPath, directory, path string, operation Operation) Result {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(fds[0]), "worker-parent")
	child := os.NewFile(uintptr(fds[1]), "worker-child")
	defer parent.Close()
	defer child.Close()
	base, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	worker, err := os.Open(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	command := exec.Command(filepath.Join(string(filepath.Separator), "proc", "self", "fd", "5"))
	command.Args = []string{"agentsh-file-lookup-broker"}
	command.Env = []string{}
	command.ExtraFiles = []*os.File{child, base, worker}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	label := ""
	if data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", "self", "attr", "current")); err == nil {
		label = strings.TrimRight(string(data), "\n\x00")
	}
	packet, err := EncodeRequest(Request{
		ID: 1, HostTID: uint32(os.Getpid()), NamespaceTID: uint32(os.Getpid()),
		StartTime: 1, Operation: operation, DirFD: int32(unix.AT_FDCWD),
		Path: path, ExpectedLabel: label,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.SendmsgN(int(parent.Fd()), packet, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, ResultPacketSize())
	n, _, flags, _, err := unix.Recvmsg(int(parent.Fd()), response, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(response) || flags&unix.MSG_TRUNC != 0 {
		t.Fatalf("invalid worker response framing n=%d flags=%#x", n, flags)
	}
	result, err := DecodeResult(response)
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("worker exit: %v", err)
	}
	return result
}
