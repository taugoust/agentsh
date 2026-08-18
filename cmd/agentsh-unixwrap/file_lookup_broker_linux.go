//go:build linux && cgo

package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	lookupproto "github.com/agentsh/agentsh/internal/filelookup"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	"golang.org/x/sys/unix"
)

const lookupWorkerTimeout = 200 * time.Millisecond

type lookupBrokerState struct {
	worker   *os.File
	devNull  *os.File
	procRoot *os.File

	baseline *lookupTaskContext
	label    string

	brokerEndpoint    *os.File
	transferEndpoint  *os.File
	payloadPID        int
	lastRequestID     uint64
	disabled          atomic.Bool
	unsupportedReason lookupproto.Reason
}

type lookupObjectIdentity struct {
	Device uint64
	Inode  uint64
	Mount  uint64
}

type lookupTaskContext struct {
	pid       int
	startTime uint64
	tgid      int
	ppid      int
	pidValue  int

	uids   [4]uint32
	gids   [4]uint32
	groups []uint32
	caps   [5]uint64
	nnp    uint32

	namespaces map[string]lookupObjectIdentity
	root       lookupObjectIdentity
	cgroup     []byte
	label      string
	task       *os.File
}

func (c *lookupTaskContext) close() {
	if c != nil && c.task != nil {
		_ = c.task.Close()
		c.task = nil
	}
}

func prepareLookupBroker(cfg *WrapperConfig) *lookupBrokerState {
	state := &lookupBrokerState{unsupportedReason: lookupproto.ReasonUnavailable}
	if cfg == nil || !cfg.FileMonitorEnabled || strings.TrimSpace(cfg.FileLookupWorkerPath) == "" {
		return state
	}
	workerPath := filepath.Clean(cfg.FileLookupWorkerPath)
	if !filepath.IsAbs(workerPath) || workerPath != cfg.FileLookupWorkerPath {
		state.unsupportedReason = lookupproto.ReasonWorkerUnavailable
		return state
	}
	workerFD, err := unix.Open(workerPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		state.unsupportedReason = lookupproto.ReasonWorkerUnavailable
		return state
	}
	state.worker = os.NewFile(uintptr(workerFD), "pinned-agentsh-file-lookup-broker")
	if state.worker == nil || !verifyStaticLookupWorker(state.worker) {
		state.close()
		state.unsupportedReason = lookupproto.ReasonWorkerUnavailable
		return state
	}
	devNullFD, err := unix.Open(filepath.Join(string(filepath.Separator), "dev", "null"), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		state.close()
		state.unsupportedReason = lookupproto.ReasonWorkerUnavailable
		return state
	}
	state.devNull = os.NewFile(uintptr(devNullFD), "lookup-worker-dev-null")
	if state.devNull == nil {
		_ = unix.Close(devNullFD)
		state.close()
		return state
	}
	if reason := unsupportedLookupLSM(); reason != lookupproto.ReasonNone {
		state.unsupportedReason = reason
		return state
	}
	state.unsupportedReason = lookupproto.ReasonContextUnavailable
	return state
}

func verifyStaticLookupWorker(worker *os.File) bool {
	if worker == nil {
		return false
	}
	info, err := worker.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return false
	}
	if _, err := worker.Seek(0, io.SeekStart); err != nil {
		return false
	}
	binary, err := elf.NewFile(worker)
	if err != nil {
		return false
	}
	defer binary.Close()
	if binary.Machine != elf.EM_X86_64 && binary.Machine != elf.EM_AARCH64 {
		return false
	}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return false
		}
	}
	_, _ = worker.Seek(0, io.SeekStart)
	return true
}

func lookupSecurityLabelRequired() bool {
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "sys", "kernel", "security", "lsm"))
	if err != nil {
		return true
	}
	for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
		switch strings.TrimSpace(name) {
		case "apparmor", "selinux", "smack":
			return true
		}
	}
	return false
}

func unsupportedLookupLSM() lookupproto.Reason {
	data, err := os.ReadFile(filepath.Join(string(filepath.Separator), "sys", "kernel", "security", "lsm"))
	if err != nil {
		return lookupproto.ReasonContextUnavailable
	}
	known := map[string]bool{
		"capability": true, "landlock": true, "yama": true, "integrity": true,
		"ima": true, "evm": true, "lockdown": true, "safesetid": true,
		"apparmor": true, "selinux": true, "bpf": true,
	}
	for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
		name = strings.TrimSpace(name)
		// BPF LSM runs in the trusted host policy domain. Broker and payload are
		// placed in the same cgroup before either can run, and AgentSH never
		// loads pathname BPF-LSM programs. Unknown LSMs remain unsupported.
		if name != "" && !known[name] {
			return lookupproto.ReasonPIDSensitiveLSM
		}
	}
	return lookupproto.ReasonNone
}

func (b *lookupBrokerState) close() {
	if b == nil {
		return
	}
	if b.baseline != nil {
		b.baseline.close()
		b.baseline = nil
	}
	for _, file := range []*os.File{b.brokerEndpoint, b.transferEndpoint, b.procRoot, b.worker, b.devNull} {
		if file != nil {
			_ = file.Close()
		}
	}
	b.brokerEndpoint = nil
	b.transferEndpoint = nil
	b.procRoot = nil
	b.worker = nil
	b.devNull = nil
}

// pinProcRoot must run after command-jail private proc installation and before
// Landlock enforcement. Ordinary execution calls it before enforcing its
// already-prepared ruleset.
func (b *lookupBrokerState) pinProcRoot() error {
	if b == nil {
		return errors.New("lookup broker state is unavailable")
	}
	if b.worker == nil || b.devNull == nil || b.unsupportedReason != lookupproto.ReasonContextUnavailable {
		return fmt.Errorf("lookup broker prerequisites are unavailable (reason=%d worker=%t devnull=%t)", b.unsupportedReason, b.worker != nil, b.devNull != nil)
	}
	if b.procRoot != nil {
		return nil
	}
	path := filepath.Join(string(filepath.Separator), "proc")
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	b.procRoot = os.NewFile(uintptr(fd), "pinned-lookup-private-proc")
	if b.procRoot == nil {
		_ = unix.Close(fd)
		return errors.New("retain private proc root")
	}
	return nil
}

func (b *lookupBrokerState) finalizeContext() error {
	if b == nil || b.procRoot == nil || b.worker == nil || b.devNull == nil {
		return errors.New("lookup broker context descriptors are unavailable")
	}
	baseline, reason, err := b.inspectTask(unix.Getpid())
	if err != nil {
		b.unsupportedReason = reason
		return err
	}
	if baseline.label == "" && lookupSecurityLabelRequired() {
		baseline.close()
		b.unsupportedReason = lookupproto.ReasonContextUnavailable
		return errors.New("required security label is unavailable")
	}
	// Effective/permitted/inheritable/ambient capabilities would make dropping
	// the worker's attack surface diverge from lookup authority. Such sessions
	// remain fully enforced but do not advertise absence probing.
	if baseline.caps[0] != 0 || baseline.caps[1] != 0 || baseline.caps[2] != 0 || baseline.caps[4] != 0 {
		baseline.close()
		b.unsupportedReason = lookupproto.ReasonCapabilityMismatch
		return errors.New("lookup broker baseline has active capabilities")
	}
	pairs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		baseline.close()
		return err
	}
	b.brokerEndpoint = os.NewFile(uintptr(pairs[0]), "lookup-broker-parent")
	b.transferEndpoint = os.NewFile(uintptr(pairs[1]), "lookup-broker-supervisor")
	if b.brokerEndpoint == nil || b.transferEndpoint == nil {
		_ = unix.Close(pairs[0])
		_ = unix.Close(pairs[1])
		baseline.close()
		return errors.New("retain lookup broker socketpair")
	}
	b.baseline = baseline
	b.label = baseline.label
	b.unsupportedReason = lookupproto.ReasonNone
	return nil
}

func (b *lookupBrokerState) attestPayload(child *payloadChild, attestation payloadAttestation) error {
	if b == nil || b.baseline == nil || child == nil || child.pid <= 0 {
		return errors.New("lookup broker baseline is unavailable")
	}
	if attestation.PID != child.pid || attestation.TID != child.pid {
		return errors.New("payload attestation identity mismatch")
	}
	secureBits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil || secureBits != attestation.SecureBits {
		return errors.New("payload securebits mismatch")
	}
	if int(b.baseline.nnp) != attestation.NoNewPrivs {
		return errors.New("payload no_new_privs mismatch")
	}
	// agentsh_fork_payload forks directly from this locked thread and its C
	// child performs no context-changing operation before this attestation.
	// Command-jail parents are intentionally non-dumpable, so reopening the
	// pre-exec child namespace links through proc can be denied even though the
	// context is exactly inherited. Bind parity to the raw-fork attestation here;
	// every actual lookup still re-inspects the post-exec target before and after
	// the worker runs.
	b.payloadPID = child.pid
	hello := lookupproto.EncodeHello(lookupproto.Hello{
		WrapperPID:      uint32(unix.Getpid()),
		PayloadPID:      uint32(child.pid),
		MaxPacketBytes:  lookupproto.MaxPacketBytes,
		WorkerTimeoutMS: uint32(lookupWorkerTimeout / time.Millisecond),
	})
	if n, err := unix.SendmsgN(int(b.brokerEndpoint.Fd()), hello, nil, nil, unix.MSG_NOSIGNAL); err != nil || n != len(hello) {
		b.unsupportedReason = lookupproto.ReasonProtocol
		return errors.New("queue lookup broker capability hello")
	}
	return nil
}

func compareLookupContexts(baseline, target *lookupTaskContext) lookupproto.Reason {
	if baseline == nil || target == nil {
		return lookupproto.ReasonContextUnavailable
	}
	for _, namespace := range []string{"user", "mnt", "pid", "cgroup"} {
		if baseline.namespaces[namespace] != target.namespaces[namespace] {
			return lookupproto.ReasonNamespaceMismatch
		}
	}
	if baseline.root != target.root {
		return lookupproto.ReasonRootMismatch
	}
	if baseline.uids != target.uids || baseline.gids != target.gids || !equalUint32s(baseline.groups, target.groups) || baseline.nnp != target.nnp {
		return lookupproto.ReasonCredentialMismatch
	}
	if baseline.caps != target.caps {
		return lookupproto.ReasonCapabilityMismatch
	}
	if baseline.label != target.label {
		return lookupproto.ReasonSecurityLabel
	}
	if !bytes.Equal(baseline.cgroup, target.cgroup) {
		return lookupproto.ReasonCgroupMismatch
	}
	return lookupproto.ReasonNone
}

func equalUint32s(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (b *lookupBrokerState) inspectTask(pid int) (*lookupTaskContext, lookupproto.Reason, error) {
	if b == nil || b.procRoot == nil || pid <= 0 {
		return nil, lookupproto.ReasonContextUnavailable, errors.New("invalid task context request")
	}
	taskFD, err := unix.Openat(int(b.procRoot.Fd()), strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, lookupproto.ReasonTaskStale, err
	}
	context := &lookupTaskContext{pid: pid, namespaces: make(map[string]lookupObjectIdentity), task: os.NewFile(uintptr(taskFD), "lookup-task-proc")}
	if context.task == nil {
		_ = unix.Close(taskFD)
		return nil, lookupproto.ReasonContextUnavailable, errors.New("retain task proc directory")
	}
	fail := func(reason lookupproto.Reason, err error) (*lookupTaskContext, lookupproto.Reason, error) {
		context.close()
		return nil, reason, err
	}
	status, err := readLookupProcFile(taskFD, "status", 256*1024)
	if err != nil {
		return fail(lookupproto.ReasonContextUnavailable, err)
	}
	if err := parseLookupStatus(status, context); err != nil {
		return fail(lookupproto.ReasonContextUnavailable, err)
	}
	context.startTime, err = readLookupStartTime(taskFD)
	if err != nil {
		return fail(lookupproto.ReasonTaskStale, err)
	}
	for _, namespace := range []string{"user", "mnt", "pid", "cgroup"} {
		fd, openErr := unix.Openat(taskFD, filepath.Join("ns", namespace), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return fail(lookupproto.ReasonNamespaceMismatch, openErr)
		}
		identity, identityErr := lookupFDIdentity(fd)
		_ = unix.Close(fd)
		if identityErr != nil {
			return fail(lookupproto.ReasonNamespaceMismatch, identityErr)
		}
		context.namespaces[namespace] = identity
	}
	rootFD, err := unix.Openat(taskFD, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(lookupproto.ReasonRootMismatch, err)
	}
	context.root, err = lookupFDIdentity(rootFD)
	_ = unix.Close(rootFD)
	if err != nil {
		return fail(lookupproto.ReasonRootMismatch, err)
	}
	context.cgroup, err = readLookupProcFile(taskFD, "cgroup", 64*1024)
	if err != nil {
		return fail(lookupproto.ReasonCgroupMismatch, err)
	}
	label, err := readLookupProcFile(taskFD, filepath.Join("attr", "current"), lookupproto.MaxLabelBytes)
	if err != nil {
		if lookupSecurityLabelRequired() {
			return fail(lookupproto.ReasonContextUnavailable, err)
		}
	} else {
		context.label = strings.TrimRight(string(label), "\n\x00")
	}
	if context.label == "" && lookupSecurityLabelRequired() {
		return fail(lookupproto.ReasonContextUnavailable, errors.New("empty required task security label"))
	}
	// Re-read start time through the pinned directory after every other field.
	startAfter, err := readLookupStartTime(taskFD)
	if err != nil || startAfter != context.startTime {
		return fail(lookupproto.ReasonTaskStale, errors.New("task identity changed while pinning context"))
	}
	return context, lookupproto.ReasonNone, nil
}

func lookupFDIdentity(fd int) (lookupObjectIdentity, error) {
	var status unix.Stat_t
	if err := unix.Fstat(fd, &status); err != nil {
		return lookupObjectIdentity{}, err
	}
	identity := lookupObjectIdentity{Device: uint64(status.Dev), Inode: status.Ino}
	var statx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &statx); err != nil {
		return lookupObjectIdentity{}, err
	}
	identity.Mount = statx.Mnt_id
	return identity, nil
}

func readLookupProcFile(dirfd int, name string, max int64) ([]byte, error) {
	if name == "" || filepath.IsAbs(name) || max <= 0 {
		return nil, errors.New("invalid proc file request")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		// attr/current is a proc-generated regular endpoint beneath a directory;
		// O_NOFOLLOW remains on the final component and does not reject "attr".
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "lookup-pinned-proc-file")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain proc file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, fmt.Errorf("read proc %s: %w", name, err)
	}
	if int64(len(data)) > max {
		return nil, errors.New("proc file exceeds bound")
	}
	return data, nil
}

func parseLookupStatus(data []byte, context *lookupTaskContext) error {
	if context == nil {
		return errors.New("nil lookup context")
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		switch name {
		case "Tgid", "Pid", "PPid", "NoNewPrivs":
			if len(fields) != 1 {
				return fmt.Errorf("invalid %s", name)
			}
			parsed, err := strconv.ParseUint(fields[0], 10, 32)
			if err != nil {
				return err
			}
			switch name {
			case "Tgid":
				context.tgid = int(parsed)
			case "Pid":
				context.pidValue = int(parsed)
			case "PPid":
				context.ppid = int(parsed)
			case "NoNewPrivs":
				context.nnp = uint32(parsed)
			}
			seen[name] = true
		case "Uid", "Gid":
			if len(fields) != 4 {
				return fmt.Errorf("invalid %s", name)
			}
			for index, field := range fields {
				parsed, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return err
				}
				if name == "Uid" {
					context.uids[index] = uint32(parsed)
				} else {
					context.gids[index] = uint32(parsed)
				}
			}
			seen[name] = true
		case "Groups":
			context.groups = context.groups[:0]
			for _, field := range fields {
				parsed, err := strconv.ParseUint(field, 10, 32)
				if err != nil {
					return err
				}
				context.groups = append(context.groups, uint32(parsed))
			}
			sort.Slice(context.groups, func(i, j int) bool { return context.groups[i] < context.groups[j] })
			seen[name] = true
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			if len(fields) != 1 {
				return fmt.Errorf("invalid %s", name)
			}
			parsed, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return err
			}
			index := map[string]int{"CapInh": 0, "CapPrm": 1, "CapEff": 2, "CapBnd": 3, "CapAmb": 4}[name]
			context.caps[index] = parsed
			seen[name] = true
		}
	}
	for _, field := range []string{"Tgid", "Pid", "PPid", "NoNewPrivs", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !seen[field] {
			return fmt.Errorf("task status omitted %s", field)
		}
	}
	return nil
}

func readLookupStartTime(dirfd int) (uint64, error) {
	data, err := readLookupProcFile(dirfd, "stat", 64*1024)
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(data))
	end := strings.LastIndex(line, ")")
	if end < 0 || end+2 >= len(line) {
		return 0, errors.New("malformed task stat")
	}
	fields := strings.Fields(line[end+2:])
	if len(fields) <= 19 {
		return 0, errors.New("task stat omitted start time")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func (b *lookupBrokerState) transferFD() int {
	if b == nil || b.transferEndpoint == nil || b.unsupportedReason != lookupproto.ReasonNone {
		return -1
	}
	return int(b.transferEndpoint.Fd())
}

func (b *lookupBrokerState) parentFD() int {
	if b == nil || b.brokerEndpoint == nil {
		return -1
	}
	return int(b.brokerEndpoint.Fd())
}

func (b *lookupBrokerState) closeTransfer() {
	if b != nil && b.transferEndpoint != nil {
		_ = b.transferEndpoint.Close()
		b.transferEndpoint = nil
	}
}

func (b *lookupBrokerState) serveOne() error {
	if b == nil || b.brokerEndpoint == nil || b.disabled.Load() {
		return errors.New("lookup broker is unavailable")
	}
	packet := make([]byte, lookupproto.MaxPacketBytes)
	n, _, flags, _, err := unix.Recvmsg(int(b.brokerEndpoint.Fd()), packet, nil, unix.MSG_DONTWAIT)
	if err != nil {
		return err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n <= 0 {
		b.disabled.Store(true)
		return errors.New("invalid lookup broker request framing")
	}
	request, err := lookupproto.DecodeRequest(packet[:n])
	if err != nil || request.ID <= b.lastRequestID {
		b.disabled.Store(true)
		return errors.New("invalid lookup broker request")
	}
	b.lastRequestID = request.ID
	result := b.classify(request)
	response, encodeErr := lookupproto.EncodeResult(result)
	if encodeErr != nil {
		b.disabled.Store(true)
		return encodeErr
	}
	written, err := unix.SendmsgN(int(b.brokerEndpoint.Fd()), response, nil, nil, unix.MSG_NOSIGNAL)
	if err != nil || written != len(response) {
		b.disabled.Store(true)
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	return nil
}

func (b *lookupBrokerState) classify(request lookupproto.Request) lookupproto.Result {
	unknown := func(reason lookupproto.Reason) lookupproto.Result {
		return lookupproto.Result{ID: request.ID, Class: lookupproto.ClassUnknown, Reason: reason}
	}
	if b == nil || b.baseline == nil || b.worker == nil || b.devNull == nil || b.disabled.Load() {
		return unknown(lookupproto.ReasonUnavailable)
	}
	lookupRequest, ok := protocolLookupRequest(request)
	if !ok || !unixmon.EligibleFileLookup(lookupRequest) {
		return unknown(lookupproto.ReasonIneligible)
	}
	target, reason, err := b.inspectTask(int(request.NamespaceTID))
	if err != nil {
		return unknown(reason)
	}
	defer target.close()
	if target.pidValue != int(request.NamespaceTID) || target.startTime != request.StartTime {
		return lookupproto.Result{ID: request.ID, Class: lookupproto.ClassStale, Reason: lookupproto.ReasonTaskStale}
	}
	if !b.targetInPayloadLineage(target) {
		return unknown(lookupproto.ReasonLineageMismatch)
	}
	if reason = compareLookupContexts(b.baseline, target); reason != lookupproto.ReasonNone {
		return unknown(reason)
	}
	base, err := b.pinLookupBase(target, request.DirFD, request.Path)
	if err != nil {
		return unknown(lookupproto.ReasonDirectoryUnavailable)
	}
	defer base.Close()

	workerRequest := request
	workerRequest.ExpectedLabel = b.label
	wire, err := lookupproto.EncodeRequest(workerRequest)
	if err != nil {
		return unknown(lookupproto.ReasonProtocol)
	}
	result := b.runWorker(base, wire, request.ID)
	if result.Class == lookupproto.ClassAbsent || result.Class == lookupproto.ClassExists {
		after, afterReason, afterErr := b.inspectTask(int(request.NamespaceTID))
		if afterErr != nil {
			return unknown(afterReason)
		}
		defer after.close()
		if after.startTime != target.startTime || compareLookupContexts(b.baseline, after) != lookupproto.ReasonNone {
			return unknown(lookupproto.ReasonTaskStale)
		}
	}
	return result
}

func protocolLookupRequest(request lookupproto.Request) (unixmon.FileLookupRequest, bool) {
	nr := int32(0)
	switch request.Operation {
	case lookupproto.OperationOpen:
		nr = unix.SYS_OPENAT
	case lookupproto.OperationOpenat2:
		nr = unix.SYS_OPENAT2
	case lookupproto.OperationStatx:
		nr = unix.SYS_STATX
	case lookupproto.OperationFstatat:
		nr = unix.SYS_NEWFSTATAT
	case lookupproto.OperationFaccessat:
		nr = unix.SYS_FACCESSAT2
	case lookupproto.OperationReadlinkMetadata:
		nr = unix.SYS_READLINKAT
	default:
		return unixmon.FileLookupRequest{}, false
	}
	lookup := unixmon.FileLookupRequest{
		TID: int(request.NamespaceTID), Syscall: nr, DirFD: request.DirFD,
		RawPath: request.Path, OpenFlags: request.OpenFlags, OpenMode: request.OpenMode,
		ResolveFlags: request.ResolveFlags, LookupFlags: request.LookupFlags,
		StatMask: request.StatMask, AccessMode: request.AccessMode,
		AccessFlags: request.AccessFlags, ReadlinkBufferLen: request.ReadlinkLen,
		PathnameNULTerminated: true,
	}
	if request.Operation == lookupproto.OperationOpenat2 {
		lookup.OpenHowSize = 24
		lookup.OpenHowParsed = true
		lookup.OpenHowTrailingBytesZero = true
	}
	return lookup, true
}

func (b *lookupBrokerState) targetInPayloadLineage(target *lookupTaskContext) bool {
	if target == nil || b.payloadPID <= 0 {
		return false
	}
	current := target.tgid
	for depth := 0; depth < 64 && current > 0; depth++ {
		if current == b.payloadPID {
			return true
		}
		context, _, err := b.inspectTask(current)
		if err != nil {
			return false
		}
		next := context.ppid
		context.close()
		if next == current {
			return false
		}
		current = next
	}
	return false
}

func (b *lookupBrokerState) pinLookupBase(target *lookupTaskContext, dirfd int32, path string) (*os.File, error) {
	if target == nil || target.task == nil {
		return nil, errors.New("target task is unavailable")
	}
	name := "root"
	if !filepath.IsAbs(path) {
		if dirfd == int32(unix.AT_FDCWD) {
			name = "cwd"
		} else if dirfd >= 0 {
			name = filepath.Join("fd", strconv.Itoa(int(dirfd)))
		} else {
			return nil, unix.EBADF
		}
	}
	fd, err := unix.Openat(int(target.task.Fd()), name, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "lookup-worker-base")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain lookup base")
	}
	return file, nil
}

func (b *lookupBrokerState) runWorker(base *os.File, request []byte, requestID uint64) lookupproto.Result {
	unknown := func(reason lookupproto.Reason) lookupproto.Result {
		return lookupproto.Result{ID: requestID, Class: lookupproto.ClassUnknown, Reason: reason}
	}
	pairs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unknown(lookupproto.ReasonWorkerUnavailable)
	}
	parent := os.NewFile(uintptr(pairs[0]), "lookup-worker-control-parent")
	child := os.NewFile(uintptr(pairs[1]), "lookup-worker-control-child")
	if parent == nil || child == nil {
		if parent != nil {
			parent.Close()
		} else {
			_ = unix.Close(pairs[0])
		}
		if child != nil {
			child.Close()
		} else {
			_ = unix.Close(pairs[1])
		}
		return unknown(lookupproto.ReasonWorkerUnavailable)
	}
	defer parent.Close()

	workerChildFD := 5
	path := filepath.Join(string(filepath.Separator), "proc", "self", "fd", strconv.Itoa(workerChildFD))
	process, err := os.StartProcess(path, []string{"agentsh-file-lookup-broker"}, &os.ProcAttr{
		Env:   []string{},
		Files: []*os.File{b.devNull, b.devNull, b.devNull, child, base, b.worker},
		Sys:   &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	})
	_ = child.Close()
	if err != nil {
		return unknown(lookupproto.ReasonWorkerUnavailable)
	}
	pid := process.Pid
	if n, sendErr := unix.SendmsgN(int(parent.Fd()), request, nil, nil, unix.MSG_NOSIGNAL); sendErr != nil || n != len(request) {
		_ = process.Kill()
		_ = waitExactChild(pid, lookupWorkerTimeout)
		_ = process.Release()
		return unknown(lookupproto.ReasonProtocol)
	}
	deadline := time.Now().Add(lookupWorkerTimeout)
	poll := []unix.PollFd{{Fd: int32(parent.Fd()), Events: unix.POLLIN}}
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
		if milliseconds > 20 {
			milliseconds = 20
		}
		n, pollErr := unix.Poll(poll, milliseconds)
		if errors.Is(pollErr, unix.EINTR) {
			continue
		}
		if pollErr != nil {
			break
		}
		if n > 0 && poll[0].Revents&unix.POLLIN != 0 {
			packet := make([]byte, lookupproto.ResultPacketSize())
			received, _, flags, _, recvErr := unix.Recvmsg(int(parent.Fd()), packet, nil, 0)
			waited := waitExactChild(pid, lookupWorkerTimeout)
			_ = process.Release()
			if recvErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || received != len(packet) || !waited {
				return unknown(lookupproto.ReasonWorkerCrash)
			}
			result, decodeErr := lookupproto.DecodeResult(packet)
			if decodeErr != nil || result.ID != requestID {
				return unknown(lookupproto.ReasonProtocol)
			}
			return result
		}
		if n > 0 && poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			break
		}
	}
	_ = process.Kill()
	if !waitExactChild(pid, 25*time.Millisecond) {
		// At most one uninterruptible worker is possible because this permanently
		// disables the session broker. Cgroup/session teardown owns the survivor.
		b.disabled.Store(true)
	}
	_ = process.Release()
	return unknown(lookupproto.ReasonTimeout)
}

func waitExactChild(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if waited == pid || errors.Is(err, syscall.ECHILD) {
			return true
		}
		if err != nil && !errors.Is(err, syscall.EINTR) {
			return false
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

func lookupProcessExitCode(status syscall.WaitStatus) int {
	if status.Exited() {
		return status.ExitStatus()
	}
	if status.Signaled() {
		return 128 + int(status.Signal())
	}
	return 127
}
