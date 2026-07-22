//go:build linux

package composition

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/landlock"
	"golang.org/x/sys/unix"
)

type BrokerConfig struct {
	HelperPath            string
	AdapterPath           string
	LauncherPath          string
	ScratchRoot           string
	ReadRoots             []string
	WriteRoots            []string
	ExecuteRoots          []string
	DenyRoots             []string
	MaxPlanOperations     int
	MaxDataBytes          int64
	RequestTimeout        time.Duration
	SetupConnection       *os.File
	SetupSenderPID        int
	SetupSenderExecutable string
	SetupSyntheticRoots   int
	SetupSyntheticRW      int
	DeviceIOCTLRoots      []string
	PublishNormalizedPlan func(parentPID, targetPID int, snapshot NormalizedPlanSnapshot)
	PublishPathMappings   func(parentPID, targetPID int, mappings PathMappings) error
}

type Broker struct {
	cfg BrokerConfig

	helper              *os.File
	adapterIdentity     os.FileInfo
	launcherIdentity    os.FileInfo
	setupSenderIdentity os.FileInfo
	setupSenderPIDFD    int

	setupReady    chan struct{}
	setup         *ReceivedSetup
	setupErr      error
	syntheticMu   sync.Mutex
	nextRoot      int
	nextSynthetic int
	closeOnce     sync.Once
}

type mappedRequester struct {
	pid        int
	pidfd      int
	proc       *os.File
	cgroup     []byte
	namespaces map[string]string
}

func (m *mappedRequester) close() {
	if m == nil {
		return
	}
	if m.pidfd >= 0 {
		_ = unix.Close(m.pidfd)
		m.pidfd = -1
	}
	if m.proc != nil {
		_ = m.proc.Close()
		m.proc = nil
	}
}

func NewBroker(cfg BrokerConfig) (*Broker, error) {
	if !filepath.IsAbs(cfg.HelperPath) {
		return nil, fmt.Errorf("composition helper path must be absolute")
	}
	if !filepath.IsAbs(cfg.AdapterPath) {
		return nil, fmt.Errorf("composition adapter path must be absolute")
	}
	if cfg.LauncherPath == "" {
		cfg.LauncherPath = filepath.Join(filepath.Dir(cfg.AdapterPath), "agentsh-composition-ns-launcher")
	}
	if !filepath.IsAbs(cfg.LauncherPath) {
		return nil, fmt.Errorf("composition namespace launcher path must be absolute")
	}
	adapterIdentity, err := os.Stat(cfg.AdapterPath)
	if err != nil {
		return nil, fmt.Errorf("stat composition adapter identity: %w", err)
	}
	if !adapterIdentity.Mode().IsRegular() {
		return nil, fmt.Errorf("composition adapter is not a regular file")
	}
	launcherIdentity, err := os.Stat(cfg.LauncherPath)
	if err != nil {
		return nil, fmt.Errorf("stat composition namespace launcher identity: %w", err)
	}
	if !launcherIdentity.Mode().IsRegular() {
		return nil, fmt.Errorf("composition namespace launcher is not a regular file")
	}
	if !filepath.IsAbs(cfg.ScratchRoot) || filepath.Clean(cfg.ScratchRoot) != cfg.ScratchRoot {
		return nil, fmt.Errorf("composition scratch root must be a clean absolute path")
	}
	resolvedScratch, err := filepath.EvalSymlinks(cfg.ScratchRoot)
	if err != nil || resolvedScratch != cfg.ScratchRoot {
		return nil, fmt.Errorf("composition scratch root must be an existing non-symlink path: %v", err)
	}
	scratchInfo, err := os.Stat(cfg.ScratchRoot)
	if err != nil || !scratchInfo.IsDir() {
		return nil, fmt.Errorf("composition scratch root must be an existing directory: %v", err)
	}
	if cfg.MaxPlanOperations <= 0 {
		return nil, fmt.Errorf("composition max plan operations must be positive")
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	cfg.ReadRoots = cleanRoots(cfg.ReadRoots)
	cfg.WriteRoots = cleanRoots(cfg.WriteRoots)
	cfg.ExecuteRoots = cleanRoots(cfg.ExecuteRoots)
	cfg.DenyRoots = cleanRoots(cfg.DenyRoots)
	cfg.DeviceIOCTLRoots = cleanRoots(cfg.DeviceIOCTLRoots)

	var setupSenderIdentity os.FileInfo
	if cfg.SetupConnection != nil {
		if cfg.SetupSenderPID <= 0 || !filepath.IsAbs(cfg.SetupSenderExecutable) {
			return nil, fmt.Errorf("composition setup sender identity is incomplete")
		}
		if cfg.SetupSyntheticRoots <= 0 || cfg.SetupSyntheticRW <= 0 {
			return nil, fmt.Errorf("composition setup synthetic pool contract is incomplete")
		}
		setupSenderIdentity, err = os.Stat(cfg.SetupSenderExecutable)
		if err != nil || !setupSenderIdentity.Mode().IsRegular() {
			return nil, fmt.Errorf("stat composition setup sender executable: %v", err)
		}
	}

	// Pin the authority-bearing helper by descriptor. Re-resolving a configured
	// pathname for every operation would let a later rename replace trusted
	// server-side code after NewBroker validated the host ceiling.
	helperFD, err := unix.Open(cfg.HelperPath, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open composition helper identity: %w", err)
	}
	helper := os.NewFile(uintptr(helperFD), "agentsh-composition-mount-helper")
	if helper == nil {
		_ = unix.Close(helperFD)
		return nil, fmt.Errorf("retain composition helper identity")
	}
	helperIdentity, err := helper.Stat()
	if err != nil || !helperIdentity.Mode().IsRegular() || helperIdentity.Mode().Perm()&0o111 == 0 {
		_ = helper.Close()
		return nil, fmt.Errorf("composition helper is not an executable regular file: %v", err)
	}

	setupSenderPIDFD := -1
	if cfg.SetupConnection != nil {
		setupSenderPIDFD, err = unix.PidfdOpen(cfg.SetupSenderPID, 0)
		if err != nil {
			_ = helper.Close()
			return nil, fmt.Errorf("pin composition setup sender: %w", err)
		}
		if !processExecutableMatches(cfg.SetupSenderPID, setupSenderIdentity) || unix.PidfdSendSignal(setupSenderPIDFD, unix.Signal(0), nil, 0) != nil {
			_ = unix.Close(setupSenderPIDFD)
			_ = helper.Close()
			return nil, fmt.Errorf("composition setup sender identity is not live and trusted")
		}
	}

	broker := &Broker{
		cfg:                 cfg,
		helper:              helper,
		adapterIdentity:     adapterIdentity,
		launcherIdentity:    launcherIdentity,
		setupSenderIdentity: setupSenderIdentity,
		setupSenderPIDFD:    setupSenderPIDFD,
	}
	if cfg.SetupConnection != nil {
		broker.setupReady = make(chan struct{})
		go broker.receiveSetup(cfg.SetupConnection)
	}
	return broker, nil
}

func (b *Broker) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		if b.cfg.SetupConnection != nil {
			_ = unix.Shutdown(int(b.cfg.SetupConnection.Fd()), unix.SHUT_RDWR)
			_ = b.cfg.SetupConnection.Close()
		}
		if b.setupReady != nil {
			<-b.setupReady
		}
		if b.setup != nil {
			b.setup.Close()
			b.setup = nil
		}
		if b.helper != nil {
			_ = b.helper.Close()
			b.helper = nil
		}
		if b.setupSenderPIDFD >= 0 {
			_ = unix.Close(b.setupSenderPIDFD)
			b.setupSenderPIDFD = -1
		}
	})
	return nil
}

func (b *Broker) receiveSetup(connection *os.File) {
	defer close(b.setupReady)
	defer connection.Close()
	b.setup, b.setupErr = ReceiveSetup(connection)
	if b.setupErr != nil {
		return
	}
	if b.setup == nil || b.setup.SenderPID != b.cfg.SetupSenderPID || b.setup.SenderUID != uint32(os.Geteuid()) || b.setup.SenderGID != uint32(os.Getegid()) || b.setupSenderPIDFD < 0 || unix.PidfdSendSignal(b.setupSenderPIDFD, unix.Signal(0), nil, 0) != nil || !processExecutableMatches(b.setup.SenderPID, b.setupSenderIdentity) {
		if b.setup != nil {
			b.setup.Close()
			b.setup = nil
		}
		b.setupErr = typedError("E_COMPOSITION_REQUESTER_CHANGED", "composition setup did not come from the trusted wrapper process")
		return
	}
	if err := b.validateSetupContract(b.setup); err != nil {
		b.setup.Close()
		b.setup = nil
		b.setupErr = err
	}
}

func (b *Broker) validateSetupContract(setup *ReceivedSetup) error {
	if setup == nil {
		return typedError("E_COMPOSITION_SETUP_INVALID", "composition setup is missing")
	}
	const knownRights = uint64(
		landlock.LANDLOCK_ACCESS_FS_EXECUTE |
			landlock.LANDLOCK_ACCESS_FS_WRITE_FILE |
			landlock.LANDLOCK_ACCESS_FS_READ_FILE |
			landlock.LANDLOCK_ACCESS_FS_READ_DIR |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			landlock.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			landlock.LANDLOCK_ACCESS_FS_MAKE_DIR |
			landlock.LANDLOCK_ACCESS_FS_MAKE_REG |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			landlock.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			landlock.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SYM |
			landlock.LANDLOCK_ACCESS_FS_REFER |
			landlock.LANDLOCK_ACCESS_FS_TRUNCATE |
			landlock.LANDLOCK_ACCESS_FS_IOCTL_DEV,
	)
	const writeRights = uint64(
		landlock.LANDLOCK_ACCESS_FS_WRITE_FILE |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			landlock.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			landlock.LANDLOCK_ACCESS_FS_MAKE_DIR |
			landlock.LANDLOCK_ACCESS_FS_MAKE_REG |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			landlock.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			landlock.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SYM |
			landlock.LANDLOCK_ACCESS_FS_REFER |
			landlock.LANDLOCK_ACCESS_FS_TRUNCATE,
	)
	exactRoot := func(path string, roots []string) bool {
		for _, root := range roots {
			if path == root {
				return true
			}
		}
		return false
	}
	rootCount, syntheticCount := 0, 0
	var syntheticRWRights uint64
	for index := range setup.Objects {
		object := &setup.Objects[index]
		if object.Rights&^knownRights != 0 {
			return typedError("E_COMPOSITION_SETUP_INVALID", "setup object %d carries unknown rights %#x", index, object.Rights&^knownRights)
		}
		switch object.Kind {
		case SetupObjectPolicy:
			readable := pathAllowed(object.Path, b.cfg.ReadRoots) || pathAllowed(object.Path, b.cfg.WriteRoots) || pathAllowed(object.Path, b.cfg.ExecuteRoots)
			if object.Rights&(landlock.LANDLOCK_ACCESS_FS_READ_FILE|landlock.LANDLOCK_ACCESS_FS_READ_DIR) != 0 && !readable {
				return typedError("E_COMPOSITION_SETUP_INVALID", "policy object %q carries read rights outside the admitted composition roots", object.Path)
			}
			if object.Rights&writeRights != 0 && !pathAllowed(object.Path, b.cfg.WriteRoots) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "policy object %q carries write rights outside the admitted composition roots", object.Path)
			}
			if object.Rights&landlock.LANDLOCK_ACCESS_FS_EXECUTE != 0 && !pathAllowed(object.Path, b.cfg.ExecuteRoots) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "policy object %q carries execute rights outside the admitted composition roots", object.Path)
			}
			if object.Rights&landlock.LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 && !exactRoot(object.Path, b.cfg.DeviceIOCTLRoots) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "policy object %q carries unadmitted device ioctl rights", object.Path)
			}
		case SetupObjectPolicyDeny:
			if !exactRoot(object.Path, b.cfg.DenyRoots) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "denied policy object %q is not in the expected deny set", object.Path)
			}
		case SetupObjectSyntheticRoot:
			rootCount++
			exact := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_EXECUTE)
			if object.Rights != exact || !pathWithin(object.Path, b.cfg.ScratchRoot) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "synthetic root %d violates its fixed rights/path class", index)
			}
		case SetupObjectSyntheticRW:
			syntheticCount++
			required := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE | landlock.LANDLOCK_ACCESS_FS_READ_DIR | landlock.LANDLOCK_ACCESS_FS_WRITE_FILE)
			forbidden := uint64(landlock.LANDLOCK_ACCESS_FS_EXECUTE | landlock.LANDLOCK_ACCESS_FS_IOCTL_DEV | landlock.LANDLOCK_ACCESS_FS_MAKE_CHAR | landlock.LANDLOCK_ACCESS_FS_MAKE_BLOCK)
			if object.Rights&required != required || object.Rights&forbidden != 0 || !pathWithin(object.Path, b.cfg.ScratchRoot) {
				return typedError("E_COMPOSITION_SETUP_INVALID", "synthetic writable object %d violates its fixed rights/path class", index)
			}
			if syntheticRWRights == 0 {
				syntheticRWRights = object.Rights
			} else if object.Rights != syntheticRWRights {
				return typedError("E_COMPOSITION_SETUP_INVALID", "synthetic writable objects carry inconsistent rights")
			}
		default:
			return typedError("E_COMPOSITION_SETUP_INVALID", "setup object %d has unknown kind %q", index, object.Kind)
		}
	}
	if rootCount != b.cfg.SetupSyntheticRoots || syntheticCount != b.cfg.SetupSyntheticRW {
		return typedError("E_COMPOSITION_SETUP_INVALID", "synthetic pool counts root=%d/%d writable=%d/%d", rootCount, b.cfg.SetupSyntheticRoots, syntheticCount, b.cfg.SetupSyntheticRW)
	}
	return nil
}

func (b *Broker) awaitSetup() error {
	if b == nil || b.setupReady == nil {
		return nil
	}
	timer := time.NewTimer(b.cfg.RequestTimeout)
	defer timer.Stop()
	select {
	case <-b.setupReady:
		if b.setupErr != nil {
			return typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "receive trusted policy objects: %v", b.setupErr)
		}
		if b.setup == nil {
			return typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "trusted policy objects are missing")
		}
		return nil
	case <-timer.C:
		return typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "trusted policy object setup timed out")
	}
}

// ServeOne validates one namespace-map handshake followed by one mount plan
// from an injected SOCK_SEQPACKET channel. Older feasibility clients may send
// the plan directly. expectedPID is the exec-notification task; every sender is
// pinned and authenticated independently.
func (b *Broker) ServeOne(connection *os.File, expectedPID int) {
	if connection == nil {
		return
	}
	defer connection.Close()
	fd := int(connection.Fd())
	expectedPIDFD, err := unix.PidfdOpen(expectedPID, 0)
	if err != nil {
		b.sendResponse(fd, typedError("E_COMPOSITION_REQUESTER_CHANGED", "pin expected adapter process: %v", err))
		return
	}
	defer unix.Close(expectedPIDFD)
	validateExpectedProcess := func() error {
		if err := unix.PidfdSendSignal(expectedPIDFD, unix.Signal(0), nil, 0); err != nil {
			return typedError("E_COMPOSITION_REQUESTER_CHANGED", "expected adapter process exited: %v", err)
		}
		return nil
	}
	if err := validateExpectedProcess(); err != nil {
		b.sendResponse(fd, err)
		return
	}
	if err := b.awaitSetup(); err != nil {
		b.sendResponse(fd, err)
		return
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		b.sendResponse(fd, fmt.Errorf("enable broker credentials: %w", err))
		return
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		b.sendResponse(fd, typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "generate request nonce: %v", err))
		return
	}
	nonce := hex.EncodeToString(nonceBytes)
	challenge, err := json.Marshal(Challenge{Version: ProtocolVersion, Type: ChallengeType, Nonce: nonce})
	if err != nil {
		b.sendResponse(fd, typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "encode request challenge: %v", err))
		return
	}
	if _, err := unix.SendmsgN(fd, challenge, nil, nil, unix.MSG_NOSIGNAL); err != nil {
		return
	}

	payload, credentials, err := b.receiveRequest(fd)
	if err != nil {
		b.sendResponse(fd, err)
		return
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		b.sendResponse(fd, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "decode broker request: %v", err))
		return
	}
	var mapped *mappedRequester
	if envelope.Type == NamespaceMapRequestType {
		if err = validateExpectedProcess(); err == nil {
			mapped, err = b.handleNamespaceMap(expectedPID, nonce, credentials, payload)
		}
		b.sendResponse(fd, err)
		if err != nil {
			return
		}
		defer mapped.close()
		payload, credentials, err = b.receiveRequest(fd)
		if err != nil {
			b.sendResponse(fd, err)
			return
		}
	} else if envelope.Type != "" {
		b.sendResponse(fd, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "unknown broker request type %q", envelope.Type))
		return
	} else if b.setup != nil {
		b.sendResponse(fd, typedError("E_COMPOSITION_NAMESPACE_INVALID", "production composition requires a namespace-map handshake"))
		return
	}
	if err := validateExpectedProcess(); err != nil {
		b.sendResponse(fd, err)
		return
	}
	b.sendResponse(fd, b.handlePlan(expectedPID, mapped, nonce, credentials, payload))
}

func (b *Broker) sendResponse(fd int, requestErr error) {
	encoded, err := json.Marshal(ErrorResponse(requestErr))
	if err == nil {
		_, _ = unix.SendmsgN(fd, encoded, nil, nil, unix.MSG_NOSIGNAL)
	}
}

func (b *Broker) receiveRequest(fd int) ([]byte, *unix.Ucred, error) {
	pollTimeout := int(b.cfg.RequestTimeout / time.Millisecond)
	pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(pollFDs, pollTimeout); err != nil || n != 1 || pollFDs[0].Revents&unix.POLLIN == 0 {
		if err == nil {
			err = errors.New("request timeout")
		}
		return nil, nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "broker request unavailable: %v", err)
	}
	payload := make([]byte, 1024*1024+1)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(fd, payload, oob, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("receive broker request: %w", err)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return nil, nil, typedError("E_COMPOSITION_LIMIT_EXCEEDED", "broker request was truncated")
	}
	if n == 0 {
		return nil, nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "broker request channel closed")
	}
	if n > 1024*1024 {
		return nil, nil, typedError("E_COMPOSITION_LIMIT_EXCEEDED", "broker request exceeds 1 MiB")
	}
	credentials, err := parseCredentials(oob[:oobn])
	if err != nil {
		return nil, nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "%v", err)
	}
	return payload[:n], credentials, nil
}

func (b *Broker) handlePlan(expectedPID int, mapped *mappedRequester, nonce string, credentials *unix.Ucred, payload []byte) error {
	if credentials == nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mount-plan credentials are missing")
	}
	requesterPID := int(credentials.Pid)
	var revalidate func() error
	if mapped != nil {
		if err := b.validateMappedRequester(expectedPID, mapped, credentials); err != nil {
			return err
		}
		revalidate = func() error { return b.validateMappedRequester(expectedPID, mapped, credentials) }
	} else {
		pidfd, err := unix.PidfdOpen(requesterPID, 0)
		if err != nil {
			return typedError("E_COMPOSITION_REQUESTER_CHANGED", "pin requester: %v", err)
		}
		defer unix.Close(pidfd)
		validatePinnedRequester := func() error {
			if err := unix.PidfdSendSignal(pidfd, unix.Signal(0), nil, 0); err != nil {
				return typedError("E_COMPOSITION_REQUESTER_CHANGED", "requester is no longer live: %v", err)
			}
			return validateRequester(expectedPID, requesterPID, credentials)
		}
		if err := validatePinnedRequester(); err != nil {
			return err
		}
		revalidate = validatePinnedRequester
	}
	plan, err := decodePlanRequest(payload, nonce, b.cfg.MaxPlanOperations)
	if err != nil {
		return err
	}
	pidOwnedByTargetUser := true
	if mapped != nil {
		if err := validatePlanNamespaceSelection(expectedPID, requesterPID, plan); err != nil {
			return err
		}
		pidOwnedByTargetUser = plan.UnsharePID
	}
	if plan.UID != nil && *plan.UID != 1 {
		return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "requested UID %d is not the admitted namespace identity", *plan.UID)
	}
	if plan.GID != nil && *plan.GID != 1 {
		return typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "requested GID %d is not the admitted namespace identity", *plan.GID)
	}
	if b.cfg.PublishNormalizedPlan != nil {
		snapshot, snapshotErr := SnapshotPlan(plan)
		if snapshotErr != nil {
			return typedError("E_COMPOSITION_COMMIT_FAILED", "%v", snapshotErr)
		}
		b.cfg.PublishNormalizedPlan(expectedPID, requesterPID, snapshot)
	}
	return b.executePlan(expectedPID, requesterPID, pidOwnedByTargetUser, plan, revalidate)
}

func validatePlanNamespaceSelection(expectedPID, requesterPID int, plan Plan) error {
	requested := map[string]bool{
		"pid":    plan.UnsharePID,
		"ipc":    plan.UnshareIPC,
		"uts":    plan.UnshareUTS,
		"cgroup": plan.UnshareCgroup,
	}
	for namespace, wantFresh := range requested {
		expected, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "ns", namespace))
		if err != nil {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "read expected %s namespace: %v", namespace, err)
		}
		actual, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID), "ns", namespace))
		if err != nil {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "read requester %s namespace: %v", namespace, err)
		}
		if (actual != expected) != wantFresh {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "requester %s namespace does not match the mount plan", namespace)
		}
	}
	return nil
}

func readPinnedProcFile(process *os.File, name string) ([]byte, error) {
	if process == nil || strings.ContainsRune(name, filepath.Separator) || name == "" {
		return nil, errors.New("invalid pinned proc file request")
	}
	fd, err := unix.Openat(int(process.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "composition-pinned-proc-"+name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain pinned proc file")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > 1024*1024 {
		return nil, errors.New("pinned proc file exceeds 1 MiB")
	}
	return contents, nil
}

func (b *Broker) handleNamespaceMap(expectedPID int, nonce string, credentials *unix.Ucred, payload []byte) (*mappedRequester, error) {
	if credentials == nil {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper credentials are missing")
	}
	requesterPID := int(credentials.Pid)
	pidfd, err := unix.PidfdOpen(requesterPID, 0)
	if err != nil {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "pin namespace mapper: %v", err)
	}
	mapped := &mappedRequester{pid: requesterPID, pidfd: pidfd}
	fail := func(err error) (*mappedRequester, error) {
		mapped.close()
		return nil, err
	}
	prefix := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID))
	procFD, err := unix.Open(prefix, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "pin namespace mapper proc directory: %v", err))
	}
	mapped.proc = os.NewFile(uintptr(procFD), "composition-namespace-mapper-proc")
	if mapped.proc == nil {
		_ = unix.Close(procFD)
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "retain namespace mapper proc directory"))
	}
	if err := unix.PidfdSendSignal(mapped.pidfd, unix.Signal(0), nil, 0); err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper exited while pinning: %v", err))
	}
	if err := b.validateNamespaceMapper(expectedPID, requesterPID, credentials); err != nil {
		return fail(err)
	}
	if _, err := decodeNamespaceMapRequest(payload, nonce); err != nil {
		return fail(err)
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		contents, err := readPinnedProcFile(mapped.proc, name)
		if err != nil || len(bytes.TrimSpace(contents)) != 0 {
			return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "%s was already configured", name))
		}
	}
	if err := b.mapNamespaceIDs(expectedPID, requesterPID, mapped.proc); err != nil {
		return fail(err)
	}
	for _, mapping := range []struct {
		name   string
		parent int
	}{{"uid_map", os.Geteuid()}, {"gid_map", os.Getegid()}} {
		contents, err := readPinnedProcFile(mapped.proc, mapping.name)
		fields := strings.Fields(string(contents))
		if err != nil || len(fields) != 3 || fields[0] != "1" || fields[1] != strconv.Itoa(mapping.parent) || fields[2] != "1" {
			return fail(typedError("E_COMPOSITION_NAMESPACE_INVALID", "verify nested %s: %q (%v)", mapping.name, contents, err))
		}
	}
	mapped.cgroup, err = readPinnedProcFile(mapped.proc, "cgroup")
	if err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "pin mapped requester cgroup: %v", err))
	}
	mapped.namespaces, err = readNamespaceIdentities(requesterPID)
	if err != nil {
		return fail(typedError("E_COMPOSITION_NAMESPACE_INVALID", "pin mapped requester namespaces: %v", err))
	}
	if err := unix.PidfdSendSignal(mapped.pidfd, unix.Signal(0), nil, 0); err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper exited during mapping: %v", err))
	}
	return mapped, nil
}

func (b *Broker) pinnedHelperCommand(extraFiles []*os.File, arguments ...string) (*exec.Cmd, error) {
	if b == nil || b.helper == nil {
		return nil, typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "pinned composition helper is unavailable")
	}
	files := append([]*os.File(nil), extraFiles...)
	helperChildFD := 3 + len(files)
	files = append(files, b.helper)
	command := exec.Command(filepath.Join(string(filepath.Separator), "proc", "self", "fd", strconv.Itoa(helperChildFD)), arguments...)
	command.ExtraFiles = files
	return command, nil
}

func (b *Broker) mapNamespaceIDs(expectedPID, requesterPID int, requesterProc *os.File) error {
	parentUserNamespace, err := os.Open(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "ns", "user"))
	if err != nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "open mapping parent user namespace: %v", err)
	}
	defer parentUserNamespace.Close()
	if requesterProc == nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "pinned namespace mapper proc directory is unavailable")
	}
	command, err := b.pinnedHelperCommand(
		[]*os.File{parentUserNamespace, requesterProc},
		"map-ids", strconv.Itoa(requesterPID), "1:1",
	)
	if err != nil {
		return err
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return typedError("E_COMPOSITION_NAMESPACE_INVALID", "map nested namespace IDs: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func processExecutableMatches(pid int, expected os.FileInfo) bool {
	if pid <= 0 || expected == nil {
		return false
	}
	actual, err := os.Stat(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "exe"))
	return err == nil && os.SameFile(actual, expected)
}

func (b *Broker) validateNamespaceMapper(expectedPID, requesterPID int, credentials *unix.Ucred) error {
	if expectedPID <= 0 || requesterPID <= 0 || credentials == nil || credentials.Uid != uint32(os.Geteuid()) || credentials.Gid != uint32(os.Getegid()) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "invalid namespace mapper identity")
	}
	if !processExecutableMatches(expectedPID, b.adapterIdentity) || !processExecutableMatches(requesterPID, b.launcherIdentity) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper executable identity is not trusted")
	}
	launcherPID, err := processParentPID(requesterPID)
	if err != nil || launcherPID <= 0 {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "read namespace mapper parent: %v", err)
	}
	launcherParent, err := processParentPID(launcherPID)
	if err != nil || launcherParent != expectedPID || !processExecutableMatches(launcherPID, b.launcherIdentity) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper is not in the adapter launcher lineage")
	}
	expectedCgroup, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "cgroup"))
	if err != nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "read expected cgroup: %v", err)
	}
	requesterCgroup, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID), "cgroup"))
	if err != nil || !bytes.Equal(expectedCgroup, requesterCgroup) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "namespace mapper left the admitted command cgroup")
	}
	expectedUser, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "ns", "user"))
	if err != nil {
		return typedError("E_COMPOSITION_NAMESPACE_INVALID", "read expected user namespace: %v", err)
	}
	requesterUser, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID), "ns", "user"))
	if err != nil || requesterUser == expectedUser {
		return typedError("E_COMPOSITION_NAMESPACE_INVALID", "namespace mapper did not create a fresh user namespace")
	}
	return nil
}

func processParentPID(pid int) (int, error) {
	contents, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if value, ok := strings.CutPrefix(line, "PPid:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, errors.New("process status omitted PPid")
}

func parseCredentials(oob []byte) (*unix.Ucred, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		credentials, err := unix.ParseUnixCredentials(&message)
		if err == nil {
			return credentials, nil
		}
	}
	return nil, errors.New("broker request did not carry SCM_CREDENTIALS")
}

func readNamespaceIdentities(pid int) (map[string]string, error) {
	identities := make(map[string]string)
	for _, namespace := range []string{"user", "mnt", "pid", "ipc", "uts", "cgroup"} {
		identity, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "ns", namespace))
		if err != nil {
			return nil, fmt.Errorf("read %s namespace: %w", namespace, err)
		}
		identities[namespace] = identity
	}
	return identities, nil
}

func (b *Broker) validateMappedRequester(expectedPID int, mapped *mappedRequester, credentials *unix.Ucred) error {
	if mapped == nil || mapped.pid <= 0 || mapped.pidfd < 0 || mapped.proc == nil || credentials == nil || int(credentials.Pid) != mapped.pid {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mount-plan sender is not the mapped namespace requester")
	}
	if credentials.Uid != uint32(os.Geteuid()) || credentials.Gid != uint32(os.Getegid()) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mapped requester credentials changed")
	}
	if !processExecutableMatches(expectedPID, b.adapterIdentity) || !processExecutableMatches(mapped.pid, b.adapterIdentity) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mount-plan executable identity is not the trusted adapter")
	}
	if err := unix.PidfdSendSignal(mapped.pidfd, unix.Signal(0), nil, 0); err != nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mapped requester is no longer live: %v", err)
	}
	if err := validateRequester(expectedPID, mapped.pid, credentials); err != nil {
		return err
	}
	launcherPID, err := processParentPID(mapped.pid)
	if err != nil || launcherPID <= 0 {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "read mapped requester parent: %v", err)
	}
	launcherParent, err := processParentPID(launcherPID)
	if err != nil || launcherParent != expectedPID || !processExecutableMatches(launcherPID, b.launcherIdentity) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mapped requester left the adapter launcher lineage")
	}
	currentCgroup, err := readPinnedProcFile(mapped.proc, "cgroup")
	if err != nil || !bytes.Equal(currentCgroup, mapped.cgroup) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mapped requester cgroup identity changed")
	}
	currentNamespaces, err := readNamespaceIdentities(mapped.pid)
	if err != nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "read mapped requester namespaces: %v", err)
	}
	for namespace, identity := range mapped.namespaces {
		if currentNamespaces[namespace] != identity {
			return typedError("E_COMPOSITION_REQUESTER_CHANGED", "mapped requester %s namespace changed", namespace)
		}
	}
	return nil
}

func validateRequester(expectedPID, requesterPID int, credentials *unix.Ucred) error {
	if expectedPID <= 0 || requesterPID <= 0 || credentials == nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "invalid requester identity")
	}
	if credentials.Uid != uint32(os.Geteuid()) || credentials.Gid != uint32(os.Getegid()) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "requester credentials do not match the supervised user")
	}
	expectedCgroup, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "cgroup"))
	if err != nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "read expected cgroup: %v", err)
	}
	requesterCgroup, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID), "cgroup"))
	if err != nil || !bytes.Equal(expectedCgroup, requesterCgroup) {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "requester left the admitted command cgroup")
	}
	for _, namespace := range []string{"user", "mnt"} {
		expected, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(expectedPID), "ns", namespace))
		if err != nil {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "read expected %s namespace: %v", namespace, err)
		}
		requester, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(requesterPID), "ns", namespace))
		if err != nil || requester == expected {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "requester did not create a fresh descendant %s namespace", namespace)
		}
	}
	return nil
}

type targetContext struct {
	pid                  int
	root                 *os.File
	user                 *os.File
	pidNS                *os.File
	mount                *os.File
	pidOwnerUser         *os.File
	pidOwnedByTargetUser bool
}

func (t *targetContext) close() {
	if t == nil {
		return
	}
	for _, file := range []*os.File{t.root, t.user, t.pidNS, t.mount, t.pidOwnerUser} {
		if file != nil {
			_ = file.Close()
		}
	}
}

// NS_GET_USERNS returns the user namespace that owns another namespace. Derive
// this from the pinned PID namespace itself rather than assuming it is owned by
// the adapter's immediate parent user namespace: a recursively composed command
// may preserve a PID namespace owned by an older ancestor.
const nsGetUserNamespace = 0xb701

func namespaceOwnerUser(namespace *os.File) (*os.File, error) {
	if namespace == nil {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "PID namespace is unavailable")
	}
	fd, _, errno := unix.Syscall(unix.SYS_IOCTL, namespace.Fd(), uintptr(nsGetUserNamespace), 0)
	if errno != 0 {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "resolve PID namespace owner: %v", errno)
	}
	unix.CloseOnExec(int(fd))
	owner := os.NewFile(fd, "composition-target-pid-owner-user-namespace")
	if owner == nil {
		_ = unix.Close(int(fd))
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "retain PID namespace owner")
	}
	return owner, nil
}

func pinTargetContext(pid int, pidOwnedByTargetUser bool) (*targetContext, error) {
	if pid <= 0 {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "invalid target pid")
	}
	before, err := readNamespaceIdentities(pid)
	if err != nil {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "read target namespaces: %v", err)
	}
	target := &targetContext{pid: pid, pidOwnedByTargetUser: pidOwnedByTargetUser}
	fail := func(err error) (*targetContext, error) {
		target.close()
		return nil, err
	}
	open := func(name, path string, flags int) (*os.File, error) {
		fd, openErr := unix.Open(path, flags|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "open target %s: %v", name, openErr)
		}
		return os.NewFile(uintptr(fd), "composition-target-"+name), nil
	}
	prefix := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid))
	if target.root, err = open("original-root", filepath.Join(prefix, "root"), unix.O_PATH|unix.O_DIRECTORY); err != nil {
		return fail(err)
	}
	if target.user, err = open("user-namespace", filepath.Join(prefix, "ns", "user"), unix.O_RDONLY); err != nil {
		return fail(err)
	}
	if target.pidNS, err = open("pid-namespace", filepath.Join(prefix, "ns", "pid"), unix.O_RDONLY); err != nil {
		return fail(err)
	}
	if target.mount, err = open("mount-namespace", filepath.Join(prefix, "ns", "mnt"), unix.O_RDONLY); err != nil {
		return fail(err)
	}
	if target.pidOwnerUser, err = namespaceOwnerUser(target.pidNS); err != nil {
		return fail(err)
	}
	ownerIsTarget, err := sameObject(target.pidOwnerUser, target.user)
	if err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "compare PID namespace owner: %v", err))
	}
	if ownerIsTarget != pidOwnedByTargetUser {
		return fail(typedError("E_COMPOSITION_NAMESPACE_INVALID", "PID namespace ownership does not match the normalized plan"))
	}
	after, err := readNamespaceIdentities(pid)
	if err != nil {
		return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "re-read target namespaces: %v", err))
	}
	for _, namespace := range []string{"user", "pid", "mnt"} {
		if before[namespace] != after[namespace] {
			return fail(typedError("E_COMPOSITION_REQUESTER_CHANGED", "target %s namespace changed while pinning", namespace))
		}
	}
	return target, nil
}

type mountExpectation struct {
	requiredAttributes uint64
	filesystem         string
	allowDescendants   bool
}

const preservedMountRestrictions = uint64(
	unix.MOUNT_ATTR_RDONLY |
		unix.MOUNT_ATTR_NOSUID |
		unix.MOUNT_ATTR_NODEV |
		unix.MOUNT_ATTR_NOEXEC |
		unix.MOUNT_ATTR_NOSYMFOLLOW,
)

const compositionMutationRights = uint64(
	landlock.LANDLOCK_ACCESS_FS_WRITE_FILE |
		landlock.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		landlock.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		landlock.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		landlock.LANDLOCK_ACCESS_FS_MAKE_DIR |
		landlock.LANDLOCK_ACCESS_FS_MAKE_REG |
		landlock.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		landlock.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		landlock.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		landlock.LANDLOCK_ACCESS_FS_MAKE_SYM |
		landlock.LANDLOCK_ACCESS_FS_REFER |
		landlock.LANDLOCK_ACCESS_FS_TRUNCATE,
)

const compositionFileRights = uint64(
	landlock.LANDLOCK_ACCESS_FS_EXECUTE |
		landlock.LANDLOCK_ACCESS_FS_WRITE_FILE |
		landlock.LANDLOCK_ACCESS_FS_READ_FILE |
		landlock.LANDLOCK_ACCESS_FS_TRUNCATE |
		landlock.LANDLOCK_ACCESS_FS_IOCTL_DEV,
)

func requiredDestinationRights(destination uint64, info os.FileInfo, mountAttributes uint64) uint64 {
	if info != nil && !info.IsDir() {
		destination &= compositionFileRights
	}
	if mountAttributes&unix.MOUNT_ATTR_RDONLY != 0 {
		destination &^= compositionMutationRights
	}
	if mountAttributes&unix.MOUNT_ATTR_NOEXEC != 0 {
		destination &^= landlock.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return destination
}

func validateDestinationRights(canonical string, sourceRights, destinationRights uint64, info os.FileInfo, mountAttributes uint64) error {
	required := requiredDestinationRights(destinationRights, info, mountAttributes)
	if sourceRights&required != required {
		return typedError(
			"E_COMPOSITION_RIGHTS_ESCALATION",
			"bind source %q rights %#x do not cover destination ancestry %#x",
			canonical,
			sourceRights,
			required,
		)
	}
	return nil
}

func (b *Broker) addBindMountExpectations(context *targetContext, expected map[string]mountExpectation, source *os.File, sourceView, target string, required uint64) error {
	output, err := b.runHelperOutput(context, source, "inspect-tree", sourceView, "")
	if err != nil {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "inspect expected bind source %q: %v", sourceView, err)
	}
	mounts, err := parseSourceMountInventory(output, sourceView)
	if err != nil {
		return err
	}
	for _, mount := range mounts {
		destination := target
		if mount.path != sourceView {
			relative, relativeErr := filepath.Rel(sourceView, mount.path)
			if relativeErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source mount %q escaped bind root %q", mount.path, sourceView)
			}
			destination = filepath.Join(target, relative)
		}
		expected[destination] = mountExpectation{
			requiredAttributes: required | mount.attributes&preservedMountRestrictions,
			filesystem:         mount.filesystem,
		}
	}
	return nil
}

func (b *Broker) finalMountExpectations(context *targetContext, staging string, plan Plan) (map[string]mountExpectation, error) {
	expected := make(map[string]mountExpectation)
	for _, operation := range plan.Operations {
		target := stagedTarget(staging, operation.Target)
		switch operation.Type {
		case OperationBind:
			source, canonical, info, err := b.openSource(context.root, operation.Source)
			if err != nil {
				if operation.Try && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return nil, err
			}
			rights, rightsErr := b.sourcePolicyRights(source, canonical, info)
			if rightsErr != nil {
				source.Close()
				return nil, rightsErr
			}
			required, requiredErr := b.bindRequiredAttributes(operation, canonical, rights, source, info)
			if requiredErr != nil {
				source.Close()
				return nil, requiredErr
			}
			expectationErr := b.addBindMountExpectations(context, expected, source, operation.Source, target, required)
			source.Close()
			if expectationErr != nil {
				return nil, expectationErr
			}
		case OperationDevBind:
			source, canonical, info, err := b.openSource(context.root, operation.Source)
			if err != nil {
				return nil, err
			}
			if _, err := b.sourcePolicyRights(source, canonical, info); err != nil {
				source.Close()
				return nil, err
			}
			expectationErr := b.addBindMountExpectations(context, expected, source, operation.Source, target, unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NOEXEC)
			source.Close()
			if expectationErr != nil {
				return nil, expectationErr
			}
		case OperationTmpfs, OperationDev:
			expected[target] = mountExpectation{requiredAttributes: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC, filesystem: "tmpfs"}
			if operation.Type == OperationDev {
				for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
					source, canonical, info, err := b.openSource(context.root, filepath.Join(string(filepath.Separator), "dev", name))
					if err != nil {
						return nil, err
					}
					if _, err := b.sourcePolicyRights(source, canonical, info); err != nil {
						source.Close()
						return nil, err
					}
					expectationErr := b.addBindMountExpectations(context, expected, source, filepath.Join(string(filepath.Separator), "dev", name), filepath.Join(target, name), unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NOEXEC)
					source.Close()
					if expectationErr != nil {
						return nil, expectationErr
					}
				}
			}
		case OperationProc:
			expected[target] = mountExpectation{requiredAttributes: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC, filesystem: "proc"}
		case OperationRemountRO:
			entry := expected[target]
			entry.requiredAttributes |= unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV
			expected[target] = entry
		}
	}
	return expected, nil
}

func (b *Broker) validateFinalTopology(context *targetContext, staging string, plan Plan) error {
	output, err := b.runHelperOutput(context, nil, "inspect-path", staging, "")
	if err != nil {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "inspect staged topology: %v", err)
	}
	mounts, err := parseSourceMountInventory(output, staging)
	if err != nil {
		return err
	}
	if len(mounts) == 0 || mounts[0].kind != 'S' {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "staged topology omitted its root")
	}
	rootRequired := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC)
	if mounts[0].attributes&rootRequired != rootRequired || mounts[0].filesystem != "tmpfs" {
		return typedError("E_COMPOSITION_RIGHTS_ESCALATION", "synthetic root lost restrictive mount attributes")
	}
	expected, err := b.finalMountExpectations(context, staging, plan)
	if err != nil {
		return err
	}
	found := make(map[string]bool, len(expected))
	for _, mount := range mounts[1:] {
		if expectation, exact := expected[mount.path]; exact {
			found[mount.path] = true
			if mount.attributes&expectation.requiredAttributes != expectation.requiredAttributes {
				return typedError("E_COMPOSITION_RIGHTS_ESCALATION", "mount %q lost required attributes (got=%#x want=%#x)", mount.path, mount.attributes, expectation.requiredAttributes)
			}
			if expectation.filesystem != "" && mount.filesystem != expectation.filesystem {
				return typedError("E_COMPOSITION_FILESYSTEM_UNSUPPORTED", "mount %q has filesystem %q, want %q", mount.path, mount.filesystem, expectation.filesystem)
			}
			continue
		}
		admitted := false
		for target, expectation := range expected {
			if expectation.allowDescendants && pathWithin(mount.path, target) {
				admitted = true
				break
			}
		}
		if !admitted {
			return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "staged topology contains unexpected mount %q", mount.path)
		}
	}
	for target := range expected {
		if !found[target] {
			return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "staged topology omitted mount %q", target)
		}
	}
	return nil
}

type completedCWDIdentity struct {
	device uint64
	inode  uint64
	mode   uint32
}

type cwdMountProvenance struct {
	index     int
	operation Operation
}

func parseCompletedCWDIdentity(output []byte, cwd string) (completedCWDIdentity, string, int, error) {
	line := strings.TrimSpace(string(output))
	fields := strings.Split(line, "\t")
	if len(fields) == 4 && fields[0] == "M" {
		errnoValue, errnoErr := strconv.Atoi(fields[1])
		length, lengthErr := strconv.Atoi(fields[2])
		decoded, decodeErr := hex.DecodeString(fields[3])
		component := string(decoded)
		if errnoErr != nil || lengthErr != nil || decodeErr != nil || length < 1 || len(decoded) != length || !filepath.IsAbs(component) || filepath.Clean(component) != component || !pathWithin(cwd, component) {
			return completedCWDIdentity{}, "", 0, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid completed cwd diagnostic")
		}
		return completedCWDIdentity{}, component, errnoValue, nil
	}
	if len(fields) != 4 || fields[0] != "O" {
		return completedCWDIdentity{}, "", 0, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid completed cwd identity")
	}
	device, deviceErr := strconv.ParseUint(fields[1], 10, 64)
	inode, inodeErr := strconv.ParseUint(fields[2], 10, 64)
	mode, modeErr := strconv.ParseUint(fields[3], 10, 32)
	if deviceErr != nil || inodeErr != nil || modeErr != nil || inode == 0 || uint32(mode)&unix.S_IFMT != unix.S_IFDIR {
		return completedCWDIdentity{}, "", 0, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid completed cwd object")
	}
	return completedCWDIdentity{device: device, inode: inode, mode: uint32(mode)}, "", 0, nil
}

func completedCWDProvenance(plan Plan) (*cwdMountProvenance, error) {
	mounts := make(map[string]cwdMountProvenance)
	for index, operation := range plan.Operations {
		if operation.Type == OperationSymlink && pathWithin(plan.Cwd, operation.Target) {
			return nil, typedError("E_COMPOSITION_CWD_UNRESOLVED", "cwd %q traverses plan symlink from operation %d", plan.Cwd, index)
		}
		switch operation.Type {
		case OperationBind, OperationDevBind, OperationTmpfs, OperationProc, OperationDev:
			for target := range mounts {
				if target == operation.Target || pathWithin(target, operation.Target) {
					delete(mounts, target)
				}
			}
			mounts[operation.Target] = cwdMountProvenance{index: index, operation: operation}
		}
	}
	var selected *cwdMountProvenance
	selectedTargetLength := -1
	for target, provenance := range mounts {
		if pathWithin(plan.Cwd, target) && len(target) > selectedTargetLength {
			copy := provenance
			selected = &copy
			selectedTargetLength = len(target)
		}
	}
	return selected, nil
}

func cwdProvenanceDescription(provenance *cwdMountProvenance) string {
	if provenance == nil {
		return "synthetic root"
	}
	operation := provenance.operation
	if operation.Source != "" {
		return fmt.Sprintf("operation %d (%s %q -> %q)", provenance.index, operation.Type, operation.Source, operation.Target)
	}
	return fmt.Sprintf("operation %d (%s %q)", provenance.index, operation.Type, operation.Target)
}

func (b *Broker) validateCompletedCWD(context *targetContext, staging string, plan Plan) error {
	output, err := b.runHelperOutput(context, nil, "inspect-cwd", staging, plan.Cwd)
	if err != nil {
		return typedError("E_COMPOSITION_CWD_UNRESOLVED", "inspect cwd %q in completed root: %v", plan.Cwd, err)
	}
	identity, missing, errnoValue, err := parseCompletedCWDIdentity(output, plan.Cwd)
	if err != nil {
		return err
	}
	provenance, err := completedCWDProvenance(plan)
	if err != nil {
		return err
	}
	if missing != "" {
		return typedError(
			"E_COMPOSITION_CWD_UNRESOLVED",
			"cwd %q first unresolved component %q (errno=%d; %s)",
			plan.Cwd,
			missing,
			errnoValue,
			cwdProvenanceDescription(provenance),
		)
	}
	if provenance == nil || (provenance.operation.Type != OperationBind && provenance.operation.Type != OperationDevBind) {
		return nil
	}
	relative, err := filepath.Rel(provenance.operation.Target, plan.Cwd)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return typedError("E_COMPOSITION_CWD_UNRESOLVED", "map cwd %q through %s", plan.Cwd, cwdProvenanceDescription(provenance))
	}
	sourcePath := provenance.operation.Source
	if relative != "." {
		sourcePath = filepath.Join(sourcePath, relative)
	}
	source, canonical, info, err := b.openSource(context.root, sourcePath)
	if err != nil {
		return typedError("E_COMPOSITION_CWD_UNRESOLVED", "resolve cwd source %q from %s: %v", sourcePath, cwdProvenanceDescription(provenance), err)
	}
	defer source.Close()
	if !info.IsDir() {
		return typedError("E_COMPOSITION_CWD_UNRESOLVED", "cwd source %q from %s is not a directory", sourcePath, cwdProvenanceDescription(provenance))
	}
	if _, err := b.sourcePolicyRights(source, canonical, info); err != nil {
		return fmt.Errorf("validate cwd source authority from %s: %w", cwdProvenanceDescription(provenance), err)
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &status); err != nil {
		return typedError("E_COMPOSITION_CWD_UNRESOLVED", "stat cwd source from %s: %v", cwdProvenanceDescription(provenance), err)
	}
	if uint64(status.Dev) != identity.device || status.Ino != identity.inode {
		return typedError(
			"E_COMPOSITION_CWD_UNRESOLVED",
			"cwd %q does not resolve to the admitted source object from %s",
			plan.Cwd,
			cwdProvenanceDescription(provenance),
		)
	}
	return nil
}

func (b *Broker) validateScratchIsolation(context *targetContext, plan Plan) error {
	for _, operation := range plan.Operations {
		if operation.Type != OperationBind && operation.Type != OperationDevBind {
			continue
		}
		source, canonical, _, err := b.openSource(context.root, operation.Source)
		if err != nil {
			if operation.Try && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "inspect bind source %q: %v", operation.Source, err)
		}
		source.Close()
		if pathWithin(canonical, b.cfg.ScratchRoot) || pathWithin(b.cfg.ScratchRoot, canonical) {
			return typedError("E_COMPOSITION_SOURCE_DENIED", "bind source %q overlaps the trusted composition staging root", canonical)
		}
	}
	return nil
}

func destinationMountRights(authorities map[string]uint64, target string) uint64 {
	var rights uint64
	longest := -1
	for mountpoint, candidate := range authorities {
		// An exact mountpoint is about to be covered. Its rule object is not in
		// the new mount's path ancestry; only the strict parent mount applies.
		if target == mountpoint || !pathWithin(target, mountpoint) {
			continue
		}
		if len(mountpoint) > longest {
			longest = len(mountpoint)
			rights = candidate
		}
	}
	return rights
}

func replaceMountAuthority(authorities map[string]uint64, target string, rights uint64) {
	for mountpoint := range authorities {
		if mountpoint == target || pathWithin(mountpoint, target) {
			delete(authorities, mountpoint)
		}
	}
	authorities[target] = rights
}

func replacePathAlias(aliases map[string]string, symlinks map[string]string, target, source string) {
	for mountpoint := range aliases {
		if mountpoint == target || pathWithin(mountpoint, target) {
			delete(aliases, mountpoint)
		}
	}
	for path := range symlinks {
		if path == target || pathWithin(path, target) {
			delete(symlinks, path)
		}
	}
	aliases[target] = source
}

func pathMappingsFromMaps(aliases, symlinks map[string]string) PathMappings {
	mappings := PathMappings{
		Aliases:  make([]PathAlias, 0, len(aliases)),
		Symlinks: make([]PathSymlink, 0, len(symlinks)),
	}
	for target, source := range aliases {
		mappings.Aliases = append(mappings.Aliases, PathAlias{Target: target, Source: source})
	}
	for target, source := range symlinks {
		mappings.Symlinks = append(mappings.Symlinks, PathSymlink{Target: target, Source: source})
	}
	sort.Slice(mappings.Aliases, func(i, j int) bool { return mappings.Aliases[i].Target < mappings.Aliases[j].Target })
	sort.Slice(mappings.Symlinks, func(i, j int) bool { return mappings.Symlinks[i].Target < mappings.Symlinks[j].Target })
	return mappings
}

func (b *Broker) executePlan(parentPID, pid int, pidOwnedByTargetUser bool, plan Plan, revalidate func() error) error {
	targetContext, err := pinTargetContext(pid, pidOwnedByTargetUser)
	if err != nil {
		return err
	}
	defer targetContext.close()
	if err := b.validateScratchIsolation(targetContext, plan); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(b.cfg.ScratchRoot, ".agentsh-bwrap-root-")
	if err != nil {
		return typedError("E_COMPOSITION_COMMIT_FAILED", "create staging directory: %v", err)
	}
	defer os.RemoveAll(staging)

	if err := b.runHelper(targetContext, nil, "private", "", ""); err != nil {
		return err
	}
	if err := b.executeSyntheticRoot(targetContext, staging); err != nil {
		return err
	}
	mountAuthorities := make(map[string]uint64)
	pathAliases := map[string]string{string(filepath.Separator): ""}
	planSymlinks := make(map[string]string)
	if b.setup != nil {
		mountAuthorities[staging] = landlock.LANDLOCK_ACCESS_FS_READ_FILE |
			landlock.LANDLOCK_ACCESS_FS_READ_DIR |
			landlock.LANDLOCK_ACCESS_FS_EXECUTE
	}
	if plan.Hostname != "" {
		if !plan.UnshareUTS {
			return typedError("E_COMPOSITION_NAMESPACE_INVALID", "hostname requires a fresh UTS namespace")
		}
		if err := b.runHelper(targetContext, nil, "hostname", plan.Hostname, ""); err != nil {
			return err
		}
	}

	for index, operation := range plan.Operations {
		target := stagedTarget(staging, operation.Target)
		parentRights := destinationMountRights(mountAuthorities, target)
		var mountedRights uint64
		mounted := false
		switch operation.Type {
		case OperationDirectory:
			err = b.runHelper(targetContext, nil, "mkdir", target, "")
		case OperationSymlink:
			err = b.runHelper(targetContext, nil, "symlink", target, operation.Source)
			if err == nil {
				planSymlinks[operation.Target] = operation.Source
			}
		case OperationTmpfs:
			mountedRights, err = b.executeSyntheticTmpfs(targetContext, target)
			mounted = err == nil
		case OperationProc:
			// A procfs for the requester's verified current PID namespace—or the
			// fresh descendant requested with --unshare-pid—contains only that
			// namespace and descendants. hidepid=2 would prevent the adapter
			// parent from writing a newly cloned child's uid_map before the map
			// gives the child a matching identity, breaking safe recursion.
			err = b.runHelper(targetContext, nil, "proc", target, "hidepid=0")
			mounted = err == nil
		case OperationDev:
			mountedRights, err = b.executeDev(targetContext, target, parentRights)
			mounted = err == nil
		case OperationDevBind:
			mountedRights, err = b.executeIdentityDevBind(targetContext, operation, target, parentRights)
			mounted = err == nil
		case OperationBind:
			mountedRights, mounted, err = b.executeBind(targetContext, operation, target, parentRights)
		case OperationRemountRO:
			err = b.runHelper(targetContext, nil, "remount-ro", target, "")
		default:
			err = typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "operation %q is unsupported", operation.Type)
		}
		if err != nil {
			return fmt.Errorf("plan operation %d (%s): %w", index, operation.Type, err)
		}
		if mounted {
			replaceMountAuthority(mountAuthorities, target, parentRights|mountedRights)
			source := ""
			if operation.Type == OperationBind || operation.Type == OperationDevBind {
				source = operation.Source
			}
			replacePathAlias(pathAliases, planSymlinks, operation.Target, source)
		}
	}
	if err := b.validateFinalTopology(targetContext, staging, plan); err != nil {
		return err
	}
	if err := b.validateCompletedCWD(targetContext, staging, plan); err != nil {
		return err
	}
	if revalidate == nil {
		return typedError("E_COMPOSITION_REQUESTER_CHANGED", "requester revalidation is unavailable")
	}
	if err := revalidate(); err != nil {
		return err
	}
	if err := b.runHelper(targetContext, nil, "pivot", staging, ""); err != nil {
		return err
	}
	if b.cfg.PublishPathMappings == nil {
		if b.setup != nil {
			return typedError("E_COMPOSITION_BACKEND_UNAVAILABLE", "composition source-attribution registry is unavailable")
		}
		return nil
	}
	if err := b.cfg.PublishPathMappings(parentPID, pid, pathMappingsFromMaps(pathAliases, planSymlinks)); err != nil {
		return typedError("E_COMPOSITION_COMMIT_FAILED", "publish composition source attribution: %v", err)
	}
	return nil
}

func (b *Broker) sourcePolicyRights(source *os.File, canonical string, info os.FileInfo) (uint64, error) {
	if source == nil || info == nil {
		return 0, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source object is unavailable")
	}
	if b.overlapsDenied(canonical, info.IsDir()) {
		return 0, typedError("E_COMPOSITION_SOURCE_DENIED", "bind source %q overlaps a denied root", canonical)
	}
	if !pathAllowed(canonical, b.cfg.ReadRoots) {
		return 0, typedError("E_COMPOSITION_SOURCE_DENIED", "bind source %q is not base-policy readable", canonical)
	}
	if b.setup == nil {
		return ^uint64(0), nil
	}
	denied, err := b.setup.DeniedPolicyObject(source, canonical)
	if err != nil {
		return 0, err
	}
	if denied {
		return 0, typedError("E_COMPOSITION_SOURCE_DENIED", "bind source %q resolves beneath a retained denied object", canonical)
	}
	rights, matched, err := b.setup.PolicyRights(source, canonical)
	if err != nil {
		return 0, err
	}
	if !matched {
		return 0, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source %q is not beneath a retained base-policy object", canonical)
	}
	readRight := uint64(landlock.LANDLOCK_ACCESS_FS_READ_FILE)
	if info.IsDir() {
		readRight = landlock.LANDLOCK_ACCESS_FS_READ_DIR
	}
	if rights&readRight == 0 {
		return 0, typedError("E_COMPOSITION_RIGHTS_ESCALATION", "source %q lacks the required base read right", canonical)
	}
	return rights, nil
}

type sourceMount struct {
	kind       byte
	id         uint64
	attributes uint64
	filesystem string
	path       string
}

func parseSourceMountInventory(output []byte, source string) ([]sourceMount, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || len(lines) > 4097 {
		return nil, typedError("E_COMPOSITION_LIMIT_EXCEEDED", "source mount inventory has %d records", len(lines))
	}
	seenIDs := make(map[uint64]struct{}, len(lines))
	seenPaths := make(map[string]struct{}, len(lines))
	mounts := make([]sourceMount, 0, len(lines))
	sourceRecords := 0
	for index, line := range lines {
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) != 5 || len(fields[0]) != 1 || fields[3] == "" || !filepath.IsAbs(fields[4]) || filepath.Clean(fields[4]) != fields[4] {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid source mount inventory record %d", index)
		}
		kind := fields[0][0]
		if kind != 'S' && kind != 'M' {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid source mount inventory kind %q", fields[0])
		}
		id, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || id == 0 {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid source mount id %q", fields[1])
		}
		attributes, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "invalid source mount attributes %q", fields[2])
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "duplicate source mount id %d", id)
		}
		if _, duplicate := seenPaths[fields[4]]; duplicate {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "stacked source mounts at %q are unsupported", fields[4])
		}
		seenIDs[id] = struct{}{}
		seenPaths[fields[4]] = struct{}{}
		if kind == 'S' {
			sourceRecords++
			if fields[4] != source {
				return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source mount inventory root changed")
			}
		} else if !pathWithin(fields[4], source) {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source submount %q escaped %q", fields[4], source)
		}
		mounts = append(mounts, sourceMount{kind: kind, id: id, attributes: attributes, filesystem: fields[3], path: fields[4]})
	}
	if sourceRecords != 1 {
		return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source mount inventory has %d roots", sourceRecords)
	}
	return mounts, nil
}

func (b *Broker) validateRecursiveSource(context *targetContext, source *os.File, canonical string, operation Operation, rootRights, destinationRights, mountAttributes uint64) ([]sourceMount, error) {
	sourceView := operation.Source
	output, err := b.runHelperOutput(context, source, "inspect-tree", sourceView, "")
	if err != nil {
		return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "inspect recursive source %q: %v", sourceView, err)
	}
	mounts, err := parseSourceMountInventory(output, sourceView)
	if err != nil {
		return nil, err
	}
	denyMasks := make(map[uint64]struct{})
	for _, denied := range b.cfg.DenyRoots {
		if denied == canonical || !pathWithin(denied, canonical) {
			continue
		}
		relativeDenied, err := filepath.Rel(canonical, denied)
		if err != nil || relativeDenied == ".." || strings.HasPrefix(relativeDenied, ".."+string(filepath.Separator)) {
			return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "map denied root %q into recursive source %q", denied, sourceView)
		}
		visibleDenied := filepath.Join(sourceView, relativeDenied)
		var mask *sourceMount
		for index := range mounts {
			candidate := &mounts[index]
			if candidate.kind != 'M' || candidate.path == sourceView || !pathWithin(visibleDenied, candidate.path) {
				continue
			}
			if mask == nil || len(candidate.path) > len(mask.path) {
				mask = candidate
			}
		}
		if mask == nil {
			return nil, typedError("E_COMPOSITION_SOURCE_DENIED", "recursive source %q contains unmasked denied root %q", sourceView, denied)
		}
		required := uint64(unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC)
		if mask.attributes&required != required {
			return nil, typedError("E_COMPOSITION_SOURCE_DENIED", "mask for denied root %q lacks restrictive mount attributes", denied)
		}
		maskedObject, maskedCanonical, _, openErr := b.openSource(context.root, visibleDenied)
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				denyMasks[mask.id] = struct{}{}
				continue
			}
			return nil, openErr
		}
		if b.setup != nil {
			isDenied, deniedErr := b.setup.DeniedPolicyObject(maskedObject, maskedCanonical)
			maskedObject.Close()
			if deniedErr != nil {
				return nil, deniedErr
			}
			if isDenied {
				return nil, typedError("E_COMPOSITION_SOURCE_DENIED", "denied root %q still resolves to its retained object", denied)
			}
		} else {
			maskedObject.Close()
		}
		denyMasks[mask.id] = struct{}{}
	}
	rootExecutable := rootRights&landlock.LANDLOCK_ACCESS_FS_EXECUTE != 0
	for _, mount := range mounts {
		if _, isMask := denyMasks[mount.id]; isMask {
			continue
		}
		pinned, childCanonical, info, err := b.openSource(context.root, mount.path)
		if err != nil {
			return nil, fmt.Errorf("resolve recursive source mount %q (%s): %w", mount.path, mount.filesystem, err)
		}
		rights, rightsErr := b.sourcePolicyRights(pinned, childCanonical, info)
		pinned.Close()
		if rightsErr != nil {
			return nil, fmt.Errorf("recursive source mount %q (%s): %w", mount.path, mount.filesystem, rightsErr)
		}
		effectiveAttributes := mountAttributes | mount.attributes&preservedMountRestrictions
		validationRights := rights
		if mount.kind == 'S' {
			// Operation-wide VFS write/execute preservation is justified by exact
			// retained descendants. Landlock still evaluates each aliased source
			// object, so the bind root itself does not inherit those permissions.
			validationRights = rootRights
		}
		if err := validateDestinationRights(childCanonical, validationRights, destinationRights, info, effectiveAttributes); err != nil {
			return nil, fmt.Errorf("recursive source mount %q (%s): %w", mount.path, mount.filesystem, err)
		}
		// A mixed recursive clone may remain VFS-rw even when this particular
		// mount node has no write right. The requester remains in the mandatory
		// Landlock domain, whose source-object rules survive aliases and deny
		// mutation here while preserving separately tagged writable descendants.
		if mount.kind == 'M' && rootExecutable && rights&landlock.LANDLOCK_ACCESS_FS_EXECUTE == 0 && mount.attributes&unix.MOUNT_ATTR_NOEXEC == 0 {
			return nil, typedError("E_COMPOSITION_RIGHTS_ESCALATION", "recursive source mount %q would gain execute authority", mount.path)
		}
	}
	return mounts, nil
}

func mountAttributeArgument(attributes uint64) string {
	var values []string
	for _, attribute := range []struct {
		bit  uint64
		name string
	}{
		{unix.MOUNT_ATTR_RDONLY, "ro"},
		{unix.MOUNT_ATTR_NOSUID, "nosuid"},
		{unix.MOUNT_ATTR_NODEV, "nodev"},
		{unix.MOUNT_ATTR_NOEXEC, "noexec"},
		{unix.MOUNT_ATTR_NOSYMFOLLOW, "nosymfollow"},
	} {
		if attributes&attribute.bit != 0 {
			values = append(values, attribute.name)
		}
	}
	return strings.Join(values, ",")
}

func bindDestination(sourceView, target, sourceMountPath string) (string, error) {
	if sourceMountPath == sourceView {
		return target, nil
	}
	relative, err := filepath.Rel(sourceView, sourceMountPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source mount %q escaped bind root %q", sourceMountPath, sourceView)
	}
	return filepath.Join(target, relative), nil
}

// cloneValidatedMountTree clones the complete source topology. The kernel
// preserves each cloned mount's existing VFS restrictions while the helper
// recursively adds the operation-wide restrictions. The broker then compares
// the attached tree with its independently captured source inventory.
func (b *Broker) cloneValidatedMountTree(context *targetContext, rootSource *os.File, mounts []sourceMount, sourceView, target string, required uint64) error {
	if len(mounts) == 0 || mounts[0].kind != 'S' || mounts[0].path != sourceView {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "recursive source %q has no pinned root mount", sourceView)
	}
	if err := b.runHelper(context, rootSource, "bind", target, mountAttributeArgument(required)+",recursive"); err != nil {
		return fmt.Errorf("clone recursive source root %q: %w", sourceView, err)
	}
	expected := make(map[string]mountExpectation, len(mounts))
	for _, mount := range mounts {
		destination, err := bindDestination(sourceView, target, mount.path)
		if err != nil {
			return err
		}
		expected[destination] = mountExpectation{
			requiredAttributes: required | mount.attributes&preservedMountRestrictions,
			filesystem:         mount.filesystem,
		}
	}
	output, err := b.runHelperOutput(context, nil, "inspect-path", target, "")
	if err != nil {
		return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "verify cloned bind tree for %q: %v", sourceView, err)
	}
	cloned, err := parseSourceMountInventory(output, target)
	if err != nil {
		return err
	}
	found := make(map[string]bool, len(expected))
	for _, mount := range cloned {
		want, ok := expected[mount.path]
		if !ok {
			return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "cloned bind %q contains unexpected mount %q", sourceView, mount.path)
		}
		found[mount.path] = true
		if mount.attributes&want.requiredAttributes != want.requiredAttributes {
			return typedError("E_COMPOSITION_RIGHTS_ESCALATION", "cloned mount %q lost attributes (got=%#x want=%#x)", mount.path, mount.attributes, want.requiredAttributes)
		}
		if mount.filesystem != want.filesystem {
			return typedError("E_COMPOSITION_FILESYSTEM_UNSUPPORTED", "cloned mount %q has filesystem %q, want %q", mount.path, mount.filesystem, want.filesystem)
		}
	}
	for path := range expected {
		if !found[path] {
			return typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "cloned bind %q omitted mount %q", sourceView, path)
		}
	}
	return nil
}

func (b *Broker) recursiveBindValidationRights(operation Operation, source *os.File, info os.FileInfo, rights uint64) (uint64, error) {
	if !operation.Recursive || info == nil || !info.IsDir() || b.setup == nil {
		return rights, nil
	}
	mutationDescendant, err := b.setup.HasRightsDescendant(source, compositionMutationRights)
	if err != nil {
		return 0, err
	}
	if mutationDescendant {
		rights |= compositionMutationRights
	}
	executableDescendant, err := b.setup.HasRightsDescendant(source, landlock.LANDLOCK_ACCESS_FS_EXECUTE)
	if err != nil {
		return 0, err
	}
	if executableDescendant {
		rights |= landlock.LANDLOCK_ACCESS_FS_EXECUTE
	}
	return rights, nil
}

func (b *Broker) bindRequiredAttributes(operation Operation, canonical string, rights uint64, source *os.File, info os.FileInfo) (uint64, error) {
	required := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV)
	writableRoot := pathAllowed(canonical, b.cfg.WriteRoots) && rights&landlock.LANDLOCK_ACCESS_FS_WRITE_FILE != 0
	executableRoot := pathAllowed(canonical, b.cfg.ExecuteRoots) && rights&landlock.LANDLOCK_ACCESS_FS_EXECUTE != 0
	writableDescendant, executableDescendant := false, false
	if operation.Recursive && info != nil && info.IsDir() && b.setup != nil {
		var err error
		writableDescendant, err = b.setup.HasRightsDescendant(source, compositionMutationRights)
		if err != nil {
			return 0, err
		}
		executableDescendant, err = b.setup.HasRightsDescendant(source, landlock.LANDLOCK_ACCESS_FS_EXECUTE)
		if err != nil {
			return 0, err
		}
	}
	// Operation-wide VFS reductions are safe only for homogeneous trees. A
	// containing bind such as /scratch may have no mutation right at its root
	// while an exact retained project descendant is writable. In that case keep
	// the clone VFS-rw and let mandatory Landlock enforce authority per source
	// object. The fixed helper performs topology operations only and never
	// content mutation. Trees such as /nix with no writable descendant are still
	// reduced recursively to read-only.
	if operation.ReadOnly || (!writableRoot && !writableDescendant) {
		required |= unix.MOUNT_ATTR_RDONLY
	}
	if !executableRoot && !executableDescendant {
		required |= unix.MOUNT_ATTR_NOEXEC
	}
	return required, nil
}

func (b *Broker) executeBind(context *targetContext, operation Operation, target string, destinationRights uint64) (uint64, bool, error) {
	source, canonical, info, err := b.openSource(context.root, operation.Source)
	if err != nil {
		if operation.Try && errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("resolve bind source %q: %w", operation.Source, err)
	}
	defer source.Close()
	rights, err := b.sourcePolicyRights(source, canonical, info)
	if err != nil {
		return 0, false, err
	}
	requiredAttributes, err := b.bindRequiredAttributes(operation, canonical, rights, source, info)
	if err != nil {
		return 0, false, err
	}
	validationRights, err := b.recursiveBindValidationRights(operation, source, info, rights)
	if err != nil {
		return 0, false, err
	}
	if err := validateDestinationRights(canonical, validationRights, destinationRights, info, requiredAttributes); err != nil {
		return 0, false, err
	}
	var mounts []sourceMount
	if operation.Recursive {
		mounts, err = b.validateRecursiveSource(context, source, canonical, operation, validationRights, destinationRights, requiredAttributes)
		if err != nil {
			return 0, false, err
		}
		if err := b.cloneValidatedMountTree(context, source, mounts, operation.Source, target, requiredAttributes); err != nil {
			return 0, false, err
		}
		return rights, true, nil
	}
	if err := b.runHelper(context, source, "bind", target, mountAttributeArgument(requiredAttributes)); err != nil {
		return 0, false, err
	}
	return rights, true, nil
}

func (b *Broker) executeIdentityDevBind(context *targetContext, operation Operation, target string, destinationRights uint64) (uint64, error) {
	if operation.Source != "/dev" || operation.Target != "/dev" || target == "" {
		return 0, typedError("E_COMPOSITION_OPTION_UNSUPPORTED", "device bind is limited to identity /dev -> /dev")
	}
	source, canonical, info, err := b.openSource(context.root, operation.Source)
	if err != nil {
		return 0, err
	}
	defer source.Close()
	if canonical != "/dev" || !info.IsDir() {
		return 0, typedError("E_COMPOSITION_SOURCE_DENIED", "identity device source is not /dev")
	}
	rights, err := b.sourcePolicyRights(source, canonical, info)
	if err != nil {
		return 0, err
	}
	requiredAttributes := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOEXEC)
	if err := validateDestinationRights(canonical, rights, destinationRights, info, requiredAttributes); err != nil {
		return 0, err
	}
	mounts, err := b.validateRecursiveSource(context, source, canonical, operation, rights, destinationRights, requiredAttributes)
	if err != nil {
		return 0, err
	}
	// Preserve device usability while tightening execution and suid semantics.
	// ABI-5 IOCTL_DEV remains independently constrained by the exact Landlock
	// device objects passed in trusted setup.
	if err := b.cloneValidatedMountTree(
		context,
		source,
		mounts,
		operation.Source,
		target,
		requiredAttributes,
	); err != nil {
		return 0, err
	}
	return rights, nil
}

func (b *Broker) executeSyntheticRoot(context *targetContext, target string) error {
	if b.setup == nil {
		return b.runHelper(context, nil, "root", target, "")
	}
	b.syntheticMu.Lock()
	defer b.syntheticMu.Unlock()
	for b.nextRoot < len(b.setup.Objects) {
		object := &b.setup.Objects[b.nextRoot]
		b.nextRoot++
		if object.Kind != SetupObjectSyntheticRoot {
			continue
		}
		if object.File == nil {
			return typedError("E_COMPOSITION_LIMIT_EXCEEDED", "synthetic root slot is already closed")
		}
		return b.runHelper(context, object.File, "bind", target, "detached,nosuid,nodev,recursive")
	}
	return typedError("E_COMPOSITION_LIMIT_EXCEEDED", "synthetic root pool exhausted")
}

func (b *Broker) executeSyntheticTmpfs(context *targetContext, target string) (uint64, error) {
	if b.setup == nil {
		// Retained only for the older feasibility harness. Production API setup
		// always supplies pre-enforcement synthetic mount objects.
		return 0, b.runHelper(context, nil, "tmpfs", target, "size=256m")
	}
	b.syntheticMu.Lock()
	defer b.syntheticMu.Unlock()
	for b.nextSynthetic < len(b.setup.Objects) {
		object := &b.setup.Objects[b.nextSynthetic]
		b.nextSynthetic++
		if object.Kind != SetupObjectSyntheticRW {
			continue
		}
		if object.File == nil {
			return 0, typedError("E_COMPOSITION_LIMIT_EXCEEDED", "synthetic mount slot is already closed")
		}
		// The helper receives a duplicate of the pre-enforcement tmpfs root and
		// mounts that tagged object at the plan destination. Slots are one-shot
		// because mount clones share their backing objects.
		if err := b.runHelper(context, object.File, "bind", target, "detached,nosuid,nodev,noexec,recursive"); err != nil {
			return 0, err
		}
		return object.Rights, nil
	}
	return 0, typedError("E_COMPOSITION_LIMIT_EXCEEDED", "synthetic mount pool exhausted")
}

func (b *Broker) executeDev(context *targetContext, target string, parentRights uint64) (uint64, error) {
	syntheticRights, err := b.executeSyntheticTmpfs(context, target)
	if err != nil {
		return 0, err
	}
	deviceDestinationRights := parentRights | syntheticRights
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		sourcePath := filepath.Join(string(filepath.Separator), "dev", name)
		source, canonical, info, err := b.openSource(context.root, sourcePath)
		if err != nil {
			return 0, err
		}
		rights, rightsErr := b.sourcePolicyRights(source, canonical, info)
		if rightsErr != nil {
			source.Close()
			return 0, rightsErr
		}
		deviceAttributes := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOEXEC)
		if rights&landlock.LANDLOCK_ACCESS_FS_WRITE_FILE == 0 {
			deviceAttributes |= unix.MOUNT_ATTR_RDONLY
		}
		if err := validateDestinationRights(canonical, rights, deviceDestinationRights, info, deviceAttributes); err != nil {
			source.Close()
			return 0, err
		}
		err = b.runHelper(context, source, "bind-device", filepath.Join(target, name), mountAttributeArgument(deviceAttributes))
		source.Close()
		if err != nil {
			return 0, err
		}
	}
	for link, destination := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := b.runHelper(context, nil, "symlink", filepath.Join(target, link), destination); err != nil {
			return 0, err
		}
	}
	return syntheticRights, nil
}

func (b *Broker) openSource(originalRoot *os.File, path string) (*os.File, string, os.FileInfo, error) {
	if originalRoot == nil {
		return nil, "", nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "pinned original root is unavailable")
	}
	relative := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	if relative == "" {
		relative = "."
	}
	fd, err := unix.Openat2(int(originalRoot.Fd()), relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, "", nil, os.ErrNotExist
		}
		return nil, "", nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "resolve source %q: %v", path, err)
	}
	file := os.NewFile(uintptr(fd), "composition-source")
	canonical, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", "self", "fd", strconv.Itoa(fd)))
	if err != nil || strings.HasSuffix(canonical, " (deleted)") || !filepath.IsAbs(canonical) {
		file.Close()
		return nil, "", nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "pin source %q", path)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, "", nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "stat source %q: %v", path, err)
	}
	return file, filepath.Clean(canonical), info, nil
}

func (b *Broker) overlapsDenied(source string, _ bool) bool {
	for _, denied := range b.cfg.DenyRoots {
		if pathWithin(source, denied) {
			return true
		}
	}
	return false
}

func (b *Broker) runHelperOutput(context *targetContext, source *os.File, operation, target, argument string) ([]byte, error) {
	if context == nil || context.root == nil || context.user == nil || context.pidNS == nil || context.mount == nil || context.pidOwnerUser == nil {
		return nil, typedError("E_COMPOSITION_REQUESTER_CHANGED", "pinned target namespaces are unavailable")
	}
	sourceOrPlaceholder := source
	if sourceOrPlaceholder == nil {
		sourceOrPlaceholder = context.root
	}
	extra := []*os.File{context.user, context.pidNS, context.mount, sourceOrPlaceholder, context.pidOwnerUser}
	pidUserMode := "parent"
	if context.pidOwnedByTargetUser {
		pidUserMode = "target"
	}
	if operation == "bind" || operation == "bind-device" {
		pidUserMode = "owner"
	}
	command, err := b.pinnedHelperCommand(extra, operation, target, argument, pidUserMode)
	if err != nil {
		return nil, err
	}
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, typedError("E_COMPOSITION_COMMIT_FAILED", "helper %s failed: %v: %s", operation, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func (b *Broker) runHelper(context *targetContext, source *os.File, operation, target, argument string) error {
	_, err := b.runHelperOutput(context, source, operation, target, argument)
	return err
}

func stagedTarget(staging, target string) string {
	return filepath.Join(staging, strings.TrimPrefix(target, string(filepath.Separator)))
}

func cleanRoots(roots []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		root = filepath.Clean(root)
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		result = append(result, root)
	}
	return result
}

func pathAllowed(path string, roots []string) bool {
	for _, root := range roots {
		if pathWithin(path, root) {
			return true
		}
	}
	return false
}

func pathWithin(path, root string) bool {
	path, root = filepath.Clean(path), filepath.Clean(root)
	if path == root {
		return true
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
