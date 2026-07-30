//go:build linux

package composition

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/landlock"
	"golang.org/x/sys/unix"
)

func TestEffectivePlanNamespaceSelectionAbsorbsPIDIsolation(t *testing.T) {
	selection := effectivePlanNamespaceSelection(Plan{
		UnsharePID:    true,
		UnshareIPC:    true,
		UnshareUTS:    true,
		UnshareCgroup: true,
	})
	if selection["pid"] {
		t.Fatal("nested composition selected a PID namespace outside the outer private procfs boundary")
	}
	for _, namespace := range []string{"ipc", "uts", "cgroup"} {
		if !selection[namespace] {
			t.Errorf("%s namespace request was not preserved", namespace)
		}
	}
}

func TestPathMappingsPreserveOnlyExplicitWritableTmpfs(t *testing.T) {
	mappings := pathMappingsFromMaps(map[string]pathAliasMapping{
		"/":     {},
		"/etc":  {freshWritable: true},
		"/proc": {source: "/proc"},
		"/nix":  {source: "/nix"},
	}, nil)
	got := make(map[string]PathAlias, len(mappings.Aliases))
	for _, alias := range mappings.Aliases {
		got[alias.Target] = alias
	}
	if !got["/etc"].FreshWritable {
		t.Fatal("writable tmpfs mapping lost fresh-writable attribution")
	}
	for _, target := range []string{"/", "/proc", "/nix"} {
		if got[target].FreshWritable {
			t.Fatalf("non-tmpfs mapping %q became fresh-writable", target)
		}
	}
	if got["/nix"].Source != "/nix" {
		t.Fatalf("bind source attribution = %q", got["/nix"].Source)
	}
	if got["/proc"].Source != "/proc" {
		t.Fatalf("private proc source attribution = %q", got["/proc"].Source)
	}
}

func newSetupTestBroker(t *testing.T, expectedPID int, expectedExecutable string, readRoots []string) (*Broker, *os.File) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(fds[0]), "setup-test-receiver")
	sender := os.NewFile(uintptr(fds[1]), "setup-test-sender")
	scratch := t.TempDir()
	broker, err := NewBroker(BrokerConfig{
		HelperPath:            self,
		AdapterPath:           self,
		LauncherPath:          self,
		ScratchRoot:           scratch,
		ReadRoots:             readRoots,
		WriteRoots:            readRoots,
		ExecuteRoots:          readRoots,
		MaxPlanOperations:     8,
		RequestTimeout:        2 * time.Second,
		SetupConnection:       receiver,
		SetupSenderPID:        expectedPID,
		SetupSenderExecutable: expectedExecutable,
		SetupSyntheticRoots:   1,
		SetupSyntheticRW:      1,
	})
	if err != nil {
		receiver.Close()
		sender.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sender.Close()
		_ = broker.Close()
	})
	return broker, sender
}

func sendSetupTestObjects(t *testing.T, sender *os.File, policyPath, scratch string, policyRights uint64) {
	t.Helper()
	policy, err := os.Open(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	rootPath := filepath.Join(scratch, "root")
	writablePath := filepath.Join(scratch, "writable")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(writablePath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writable, err := os.Open(writablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	rootRights := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_EXECUTE)
	writableRights := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_WRITE_FILE)
	if err := SendSetup(
		sender,
		Mode,
		[]SetupObjectKind{SetupObjectPolicy, SetupObjectSyntheticRoot, SetupObjectSyntheticRW},
		[]string{policyPath, rootPath, writablePath},
		[]uint64{policyRights, rootRights, writableRights},
		[]*os.File{policy, root, writable},
	); err != nil {
		t.Fatal(err)
	}
}

func TestCompositionSetupSenderHelper(t *testing.T) {
	if os.Getenv("AGENTSH_TEST_SETUP_SENDER") != "1" {
		return
	}
	sender := os.NewFile(3, "setup-sender")
	policy := os.NewFile(4, "setup-policy")
	root := os.NewFile(5, "setup-root")
	writable := os.NewFile(6, "setup-writable")
	defer sender.Close()
	defer policy.Close()
	defer root.Close()
	defer writable.Close()
	rootRights := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_EXECUTE)
	writableRights := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_WRITE_FILE)
	if err := SendSetup(
		sender,
		Mode,
		[]SetupObjectKind{SetupObjectPolicy, SetupObjectSyntheticRoot, SetupObjectSyntheticRW},
		[]string{os.Getenv("AGENTSH_TEST_POLICY_PATH"), os.Getenv("AGENTSH_TEST_ROOT_PATH"), os.Getenv("AGENTSH_TEST_WRITABLE_PATH")},
		[]uint64{landlock.LANDLOCK_ACCESS_FS_READ_DIR, rootRights, writableRights},
		[]*os.File{policy, root, writable},
	); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AGENTSH_TEST_SETUP_HOLD") == "1" {
		barrier := os.NewFile(7, "setup-sender-barrier")
		if barrier == nil {
			t.Fatal("setup sender barrier is unavailable")
		}
		defer barrier.Close()
		_, _ = io.Copy(io.Discard, barrier)
	}
}

func TestBrokerPinsHelperAcrossPathReplacement(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	helper := filepath.Join(directory, "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf original"), 0o700); err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(BrokerConfig{
		HelperPath:        helper,
		AdapterPath:       self,
		LauncherPath:      self,
		ScratchRoot:       directory,
		MaxPlanOperations: 1,
		RequestTimeout:    time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nprintf replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, helper); err != nil {
		t.Fatal(err)
	}
	command, err := broker.pinnedHelperCommand(nil)
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("execute pinned helper: %v: %s", err, output)
	}
	if string(output) != "original" {
		t.Fatalf("pinned helper output = %q", output)
	}
}

func TestBrokerCloseUnblocksUnpublishedSetupReceive(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	broker, _ := newSetupTestBroker(t, os.Getpid(), self, []string{t.TempDir()})
	done := make(chan error, 1)
	go func() { done <- broker.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker close did not unblock setup receive")
	}
}

func TestBrokerSetupTimeoutFailsClosedAndCloseUnblocksReceiver(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	broker, _ := newSetupTestBroker(t, os.Getpid(), self, []string{t.TempDir()})
	broker.cfg.RequestTimeout = 50 * time.Millisecond
	if err := broker.awaitSetup(); err == nil || !strings.Contains(err.Error(), "setup timed out") {
		t.Fatalf("setup timeout error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- broker.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker close did not unblock setup receiver after timeout")
	}
}

func TestBrokerRequestTimeoutReturnsTypedFailureAndClosesConnection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(BrokerConfig{
		HelperPath: self, AdapterPath: self, LauncherPath: self,
		ScratchRoot: t.TempDir(), MaxPlanOperations: 1, RequestTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := os.NewFile(uintptr(fds[0]), "request-timeout-server")
	client := os.NewFile(uintptr(fds[1]), "request-timeout-client")
	defer client.Close()
	done := make(chan struct{})
	go func() {
		broker.ServeOne(server, os.Getpid())
		close(done)
	}()

	packet := make([]byte, 4096)
	n, err := client.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	var challenge Challenge
	if err := json.Unmarshal(packet[:n], &challenge); err != nil || challenge.Type != ChallengeType {
		t.Fatalf("challenge=%+v err=%v", challenge, err)
	}
	n, err = client.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(packet[:n], &response); err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Code != "E_COMPOSITION_REQUESTER_CHANGED" || !strings.Contains(response.Message, "timeout") {
		t.Fatalf("timeout response = %+v", response)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ServeOne did not close after request timeout")
	}
}

func TestBrokerRejectsSetupAfterTrustedSenderExit(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(fds[0]), "exited-sender-receiver")
	sender := os.NewFile(uintptr(fds[1]), "exited-sender-sender")
	defer receiver.Close()
	defer sender.Close()

	admitted := t.TempDir()
	scratch := t.TempDir()
	rootPath := filepath.Join(scratch, "root")
	writablePath := filepath.Join(scratch, "writable")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(writablePath, 0o700); err != nil {
		t.Fatal(err)
	}
	policy, err := os.Open(admitted)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writable, err := os.Open(writablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()

	command := exec.Command(self, "-test.run=^TestCompositionSetupSenderHelper$")
	command.Env = append(os.Environ(),
		"AGENTSH_TEST_SETUP_SENDER=1",
		"AGENTSH_TEST_POLICY_PATH="+admitted,
		"AGENTSH_TEST_ROOT_PATH="+rootPath,
		"AGENTSH_TEST_WRITABLE_PATH="+writablePath,
	)
	command.ExtraFiles = []*os.File{sender, policy, root, writable}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("setup sender helper: %v: %s", err, output)
	}
	if err := sender.Close(); err != nil {
		t.Fatal(err)
	}

	broker, err := NewBroker(BrokerConfig{
		HelperPath:            self,
		AdapterPath:           self,
		LauncherPath:          self,
		ScratchRoot:           scratch,
		ReadRoots:             []string{admitted},
		WriteRoots:            []string{admitted},
		ExecuteRoots:          []string{admitted},
		MaxPlanOperations:     8,
		RequestTimeout:        time.Second,
		SetupConnection:       receiver,
		SetupSenderPID:        command.ProcessState.Pid(),
		SetupSenderExecutable: self,
		SetupSyntheticRoots:   1,
		SetupSyntheticRW:      1,
	})
	if err == nil {
		defer broker.Close()
		err = broker.awaitSetup()
	}
	if err == nil || (!strings.Contains(err.Error(), "pin composition setup sender") && !strings.Contains(err.Error(), "not live and trusted") && !strings.Contains(err.Error(), "E_COMPOSITION_REQUESTER_CHANGED")) {
		t.Fatalf("exited setup sender error = %v", err)
	}
}

func TestBrokerRejectsSetupFromSubstitutedSenderPID(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	admitted := t.TempDir()
	broker, sender := newSetupTestBroker(t, os.Getpid(), self, []string{admitted})
	rootPath := filepath.Join(broker.cfg.ScratchRoot, "root")
	writablePath := filepath.Join(broker.cfg.ScratchRoot, "writable")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(writablePath, 0o700); err != nil {
		t.Fatal(err)
	}
	policy, err := os.Open(admitted)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	writable, err := os.Open(writablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer writable.Close()
	barrierRead, barrierWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(self, "-test.run=^TestCompositionSetupSenderHelper$")
	command.Env = append(os.Environ(),
		"AGENTSH_TEST_SETUP_SENDER=1",
		"AGENTSH_TEST_SETUP_HOLD=1",
		"AGENTSH_TEST_POLICY_PATH="+admitted,
		"AGENTSH_TEST_ROOT_PATH="+rootPath,
		"AGENTSH_TEST_WRITABLE_PATH="+writablePath,
	)
	command.ExtraFiles = []*os.File{sender, policy, root, writable, barrierRead}
	if err := command.Start(); err != nil {
		barrierRead.Close()
		barrierWrite.Close()
		t.Fatal(err)
	}
	barrierRead.Close()
	defer func() {
		_ = barrierWrite.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	if err := broker.awaitSetup(); err == nil || !strings.Contains(err.Error(), "E_COMPOSITION_REQUESTER_CHANGED") {
		t.Fatalf("setup sender mismatch error = %v", err)
	}
	if err := barrierWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerRejectsSetupFromWrongExecutableIdentity(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	impostor := filepath.Join(t.TempDir(), "impostor")
	if err := os.WriteFile(impostor, []byte("not the test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(fds[0]), "wrong-identity-receiver")
	sender := os.NewFile(uintptr(fds[1]), "wrong-identity-sender")
	defer receiver.Close()
	defer sender.Close()
	_, err = NewBroker(BrokerConfig{
		HelperPath: self, AdapterPath: self, LauncherPath: self,
		ScratchRoot: t.TempDir(), ReadRoots: []string{t.TempDir()},
		MaxPlanOperations: 1, RequestTimeout: time.Second,
		SetupConnection: receiver, SetupSenderPID: os.Getpid(), SetupSenderExecutable: impostor,
		SetupSyntheticRoots: 1, SetupSyntheticRW: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "not live and trusted") {
		t.Fatalf("setup executable mismatch error = %v (self=%s)", err, self)
	}
}

func TestDestinationRightsCannotBroadenWritableSyntheticAncestor(t *testing.T) {
	directory := t.TempDir()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	read := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR)
	destination := read | landlock.LANDLOCK_ACCESS_FS_WRITE_FILE | landlock.LANDLOCK_ACCESS_FS_MAKE_REG
	if err := validateDestinationRights(directory, read, destination, info, unix.MOUNT_ATTR_NOSUID); err == nil || !strings.Contains(err.Error(), "E_COMPOSITION_RIGHTS_ESCALATION") {
		t.Fatalf("writable destination escalation error = %v", err)
	}
	if err := validateDestinationRights(directory, read, destination, info, unix.MOUNT_ATTR_RDONLY); err != nil {
		t.Fatalf("read-only mount did not neutralize destination mutation rights: %v", err)
	}
}

func TestBrokerRequiresSyntheticConstructionPathsRemoved(t *testing.T) {
	scratch := t.TempDir()
	constructionPath := filepath.Join(scratch, "pool", "slot")
	if err := os.MkdirAll(constructionPath, 0o700); err != nil {
		t.Fatal(err)
	}
	broker := &Broker{cfg: BrokerConfig{
		ScratchRoot:              scratch,
		RequireSetupPathsRemoved: true,
	}}
	if err := broker.validateSyntheticConstructionPathRemoved(0, constructionPath); err == nil || !strings.Contains(err.Error(), "remained visible") {
		t.Fatalf("visible construction path error = %v", err)
	}
	if err := os.RemoveAll(filepath.Join(scratch, "pool")); err != nil {
		t.Fatal(err)
	}
	if err := broker.validateSyntheticConstructionPathRemoved(0, constructionPath); err != nil {
		t.Fatalf("removed construction path rejected: %v", err)
	}
}

func TestListOnlySetupObjectCannotCarryFileReadAuthority(t *testing.T) {
	directory := t.TempDir()
	broker := &Broker{cfg: BrokerConfig{ListRoots: []string{directory}}}
	setup := &ReceivedSetup{Objects: []ReceivedSetupObject{{
		SetupObject: SetupObject{
			Kind:   SetupObjectPolicy,
			Path:   directory,
			Rights: landlock.LANDLOCK_ACCESS_FS_READ_DIR,
		},
	}}}
	if err := broker.validateSetupContract(setup); err != nil {
		t.Fatalf("directory-list setup object was rejected: %v", err)
	}
	setup.Objects[0].Rights |= landlock.LANDLOCK_ACCESS_FS_READ_FILE
	if err := broker.validateSetupContract(setup); err == nil || !strings.Contains(err.Error(), "file-read rights") {
		t.Fatalf("list-only setup object carried file-read authority: %v", err)
	}
}

func TestListOnlySourceAuthorizationExcludesRootRuleAndRegularFiles(t *testing.T) {
	directory := t.TempDir()
	child := filepath.Join(directory, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(child, "secret")
	if err := os.WriteFile(regular, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	openWithInfo := func(path string) (*os.File, os.FileInfo) {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		return file, info
	}

	childFile, childInfo := openWithInfo(child)
	broker := &Broker{cfg: BrokerConfig{ListRoots: []string{directory}}}
	if _, err := broker.sourcePolicyRights(childFile, child, childInfo); err != nil {
		t.Fatalf("specific list root did not admit a directory descendant: %v", err)
	}

	regularFile, regularInfo := openWithInfo(regular)
	if _, err := broker.sourcePolicyRights(regularFile, regular, regularInfo); err == nil {
		t.Fatal("specific list root admitted a regular-file bind source")
	}

	rootOnly := &Broker{cfg: BrokerConfig{ListRoots: []string{"/"}}}
	if _, err := rootOnly.sourcePolicyRights(childFile, child, childInfo); err == nil {
		t.Fatal("root discovery authority admitted an arbitrary directory bind source")
	}
}

func TestListOnlyDirectoryBindFitsSyntheticRootAfterReadOnlyNoExecReduction(t *testing.T) {
	directory := t.TempDir()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	listOnly := uint64(landlock.LANDLOCK_ACCESS_FS_READ_DIR)
	destination := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_EXECUTE)
	attributes := uint64(unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOEXEC)
	source, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	broker := &Broker{cfg: BrokerConfig{ListRoots: []string{directory}}, setup: &ReceivedSetup{}}
	validationRights, err := broker.recursiveBindValidationRights(
		Operation{Type: OperationBind, Source: directory, Target: "/metadata", Recursive: true},
		source,
		info,
		listOnly,
	)
	if err != nil {
		t.Fatal(err)
	}
	if validationRights&landlock.LANDLOCK_ACCESS_FS_READ_FILE == 0 {
		t.Fatalf("validation rights %#x omitted synthetic-root read compatibility", validationRights)
	}
	if err := validateDestinationRights(directory, validationRights, destination, info, attributes); err != nil {
		t.Fatalf("list-only directory bind was rejected after safe reductions: %v", err)
	}
	if !listPathAllowed("/scratch/theo", []string{"/", "/scratch"}) {
		t.Fatal("specific list root did not cover its directory descendant")
	}
	if listPathAllowed("/root", []string{"/"}) {
		t.Fatal("root discovery authority became generic bind-source authority")
	}
}

func TestBindWithoutBaseWriteAuthorityIsReducedToReadOnly(t *testing.T) {
	readExecute := uint64(
		landlock.LANDLOCK_ACCESS_FS_READ_FILE |
			landlock.LANDLOCK_ACCESS_FS_READ_DIR |
			landlock.LANDLOCK_ACCESS_FS_EXECUTE,
	)
	broker := &Broker{cfg: BrokerConfig{
		WriteRoots:   []string{"/workspace"},
		ExecuteRoots: []string{"/nix"},
	}}
	operation := Operation{Type: OperationBind, Source: "/nix", Target: "/nix", Recursive: true}
	attributes, err := broker.bindRequiredAttributes(operation, "/nix", readExecute, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&unix.MOUNT_ATTR_RDONLY == 0 {
		t.Fatalf("non-writable /nix bind attributes = %#x, want read-only", attributes)
	}
	if attributes&unix.MOUNT_ATTR_NOEXEC != 0 {
		t.Fatalf("executable /nix bind attributes = %#x, did not want noexec", attributes)
	}

	broker.cfg.WriteRoots = []string{"/nix"}
	attributes, err = broker.bindRequiredAttributes(operation, "/nix", readExecute|landlock.LANDLOCK_ACCESS_FS_WRITE_FILE, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&unix.MOUNT_ATTR_RDONLY != 0 {
		t.Fatalf("base-policy writable bind attributes = %#x, did not want read-only", attributes)
	}
}

func TestHeterogeneousBindPreservesRetainedWritableDescendant(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "theo", "qshell-project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	openPath := func(path string) *os.File {
		t.Helper()
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		return os.NewFile(uintptr(fd), path)
	}
	source := openPath(root)
	defer source.Close()
	projectObject := openPath(project)
	defer projectObject.Close()
	projectMetadata, err := objectMetadata(SetupObjectPolicy, project, compositionMutationRights|landlock.LANDLOCK_ACCESS_FS_READ_DIR|landlock.LANDLOCK_ACCESS_FS_EXECUTE, projectObject)
	if err != nil {
		t.Fatal(err)
	}
	broker := &Broker{
		cfg: BrokerConfig{
			WriteRoots:   []string{project},
			ExecuteRoots: []string{project},
		},
		setup: &ReceivedSetup{Objects: []ReceivedSetupObject{{SetupObject: projectMetadata, File: projectObject}}},
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	operation := Operation{Type: OperationBind, Source: root, Target: "/scratch", Recursive: true}
	rootRights := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR)
	attributes, err := broker.bindRequiredAttributes(operation, root, rootRights, source, info)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&unix.MOUNT_ATTR_RDONLY != 0 {
		t.Fatalf("heterogeneous bind attributes=%#x, writable descendant was flattened to read-only", attributes)
	}
	if attributes&unix.MOUNT_ATTR_NOEXEC != 0 {
		t.Fatalf("heterogeneous bind attributes=%#x, executable descendant was flattened to noexec", attributes)
	}
	validationRights, err := broker.recursiveBindValidationRights(operation, source, info, rootRights)
	if err != nil {
		t.Fatal(err)
	}
	wantValidationRights := rootRights | compositionMutationRights | landlock.LANDLOCK_ACCESS_FS_EXECUTE
	if validationRights&wantValidationRights != wantValidationRights {
		t.Fatalf("heterogeneous validation rights=%#x, want coverage %#x", validationRights, wantValidationRights)
	}
	if err := validateDestinationRights(root, validationRights, wantValidationRights, info, attributes); err != nil {
		t.Fatalf("heterogeneous bind did not preserve descendant authority: %v", err)
	}

	broker.setup.Objects[0].Rights = landlock.LANDLOCK_ACCESS_FS_READ_DIR
	attributes, err = broker.bindRequiredAttributes(operation, root, rootRights, source, info)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&unix.MOUNT_ATTR_RDONLY == 0 || attributes&unix.MOUNT_ATTR_NOEXEC == 0 {
		t.Fatalf("homogeneous non-writable bind attributes=%#x, want ro,noexec", attributes)
	}
	validationRights, err = broker.recursiveBindValidationRights(operation, source, info, rootRights)
	if err != nil {
		t.Fatal(err)
	}
	if validationRights != rootRights {
		t.Fatalf("homogeneous validation rights=%#x, want %#x", validationRights, rootRights)
	}
}

func TestBrokerRejectsScratchRootAsBindSourceOrDescendant(t *testing.T) {
	scratch := t.TempDir()
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(rootFD), "test-root")
	defer root.Close()
	broker := &Broker{cfg: BrokerConfig{ScratchRoot: scratch}}
	context := &targetContext{root: root}

	for _, source := range []string{scratch, filepath.Join(scratch, "child"), string(filepath.Separator)} {
		if source != string(filepath.Separator) {
			if err := os.MkdirAll(source, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		err := broker.validateScratchIsolation(context, Plan{Operations: []Operation{{Type: OperationBind, Source: source, Target: "/target", Recursive: true}}})
		if err == nil || !strings.Contains(err.Error(), "E_COMPOSITION_SOURCE_DENIED") {
			t.Errorf("scratch-overlapping source %q error = %v", source, err)
		}
	}
}

func TestBrokerRejectsSetupRightsOutsideServerCeiling(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	admitted := t.TempDir()
	outside := t.TempDir()
	broker, sender := newSetupTestBroker(t, os.Getpid(), self, []string{admitted})
	sendSetupTestObjects(t, sender, outside, broker.cfg.ScratchRoot, landlock.LANDLOCK_ACCESS_FS_READ_DIR)
	if err := broker.awaitSetup(); err == nil || !strings.Contains(err.Error(), "E_COMPOSITION_SETUP_INVALID") {
		t.Fatalf("setup rights ceiling error = %v", err)
	}
}
