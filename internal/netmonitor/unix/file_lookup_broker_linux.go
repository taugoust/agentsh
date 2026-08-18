//go:build linux && cgo

package unix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lookupproto "github.com/agentsh/agentsh/internal/filelookup"
	"golang.org/x/sys/unix"
)

const (
	defaultFileLookupTimeout = 250 * time.Millisecond
	maxFileLookupTimeout     = 2 * time.Second
	globalFileLookupLimit    = 32
)

var fileLookupGlobalAdmission = make(chan struct{}, globalFileLookupLimit)

type FileLookupBrokerConfig struct {
	Endpoint           *os.File
	ExpectedWrapperPID int
	ExpectedPayloadPID int
	Timeout            time.Duration
}

type lineageFileLookupBroker struct {
	endpoint *os.File
	fd       int
	timeout  time.Duration
	nextID   atomic.Uint64
	admit    chan struct{}

	mu       sync.Mutex
	closed   bool
	disabled bool
}

// NewFileLookupBroker authenticates and binds one private wrapper endpoint.
// Failure is returned to setup code as optional probe unavailability; it must
// not be converted into an allow or an absent result.
func NewFileLookupBroker(cfg FileLookupBrokerConfig) (FileLookupBroker, error) {
	if cfg.Endpoint == nil {
		return nil, errors.New("file lookup broker endpoint is unavailable")
	}
	fd := int(cfg.Endpoint.Fd())
	if fd < 0 {
		return nil, errors.New("invalid file lookup broker endpoint")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultFileLookupTimeout
	}
	if cfg.Timeout > maxFileLookupTimeout {
		cfg.Timeout = maxFileLookupTimeout
	}
	if cfg.Timeout < 25*time.Millisecond {
		cfg.Timeout = 25 * time.Millisecond
	}
	if cfg.ExpectedWrapperPID <= 0 || cfg.ExpectedPayloadPID <= 0 {
		return nil, errors.New("file lookup broker process identity is incomplete")
	}
	peer, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("authenticate file lookup broker endpoint: %w", err)
	}
	if int(peer.Pid) != cfg.ExpectedWrapperPID {
		return nil, fmt.Errorf("file lookup broker peer pid %d does not match wrapper pid %d", peer.Pid, cfg.ExpectedWrapperPID)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("make file lookup broker endpoint nonblocking: %w", err)
	}

	deadline := time.Now().Add(cfg.Timeout)
	helloPacket, err := receiveLookupPacket(context.Background(), fd, lookupproto.HelloPacketSize(), deadline)
	if err != nil {
		return nil, fmt.Errorf("receive file lookup broker hello: %w", err)
	}
	hello, err := lookupproto.DecodeHello(helloPacket)
	if err != nil {
		return nil, err
	}
	// PIDs in the hello are viewed in the wrapper's PID namespace and are
	// capability diagnostics only. Host identities are authenticated by
	// SCM_CREDENTIALS in the handoff and SO_PEERCRED above.
	if hello.MaxPacketBytes > lookupproto.MaxPacketBytes || time.Duration(hello.WorkerTimeoutMS)*time.Millisecond > maxFileLookupTimeout {
		return nil, errors.New("file lookup broker advertised unsupported limits")
	}

	return &lineageFileLookupBroker{
		endpoint: cfg.Endpoint,
		fd:       fd,
		timeout:  cfg.Timeout,
		admit:    make(chan struct{}, 1),
	}, nil
}

func (b *lineageFileLookupBroker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	endpoint := b.endpoint
	b.endpoint = nil
	b.mu.Unlock()
	if endpoint != nil {
		return endpoint.Close()
	}
	return nil
}

func (b *lineageFileLookupBroker) disable() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.disabled = true
	endpoint := b.endpoint
	b.endpoint = nil
	b.closed = true
	b.mu.Unlock()
	if endpoint != nil {
		_ = endpoint.Close()
	}
}

func (b *lineageFileLookupBroker) availableFD() (int, bool) {
	if b == nil {
		return -1, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.disabled || b.endpoint == nil {
		return -1, false
	}
	return b.fd, true
}

func (b *lineageFileLookupBroker) ProbeFileLookup(ctx context.Context, req FileLookupRequest) FileLookupResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if !EligibleFileLookup(req) {
		return unknownFileLookup(LookupReasonIneligible)
	}
	fd, ok := b.availableFD()
	if !ok {
		return unknownFileLookup(LookupReasonUnavailable)
	}
	select {
	case b.admit <- struct{}{}:
		defer func() { <-b.admit }()
	default:
		return unknownFileLookup(LookupReasonAdmission)
	}
	select {
	case fileLookupGlobalAdmission <- struct{}{}:
		defer func() { <-fileLookupGlobalAdmission }()
	default:
		return unknownFileLookup(LookupReasonAdmission)
	}

	identity, err := pinLookupTask(req.TID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return FileLookupResult{Class: LookupStale, Reason: LookupReasonTaskStale}
		}
		return unknownFileLookup(LookupReasonContextUnavailable)
	}
	defer identity.close()

	op, ok := fileLookupOperation(req.Syscall)
	if !ok {
		return unknownFileLookup(LookupReasonIneligible)
	}
	id := b.nextID.Add(1)
	if id == 0 {
		id = b.nextID.Add(1)
	}
	wire, err := lookupproto.EncodeRequest(lookupproto.Request{
		ID:           id,
		HostTID:      uint32(req.TID),
		NamespaceTID: uint32(identity.namespaceTID),
		StartTime:    identity.startTime,
		Operation:    op,
		DirFD:        req.DirFD,
		OpenFlags:    req.OpenFlags,
		OpenMode:     req.OpenMode,
		ResolveFlags: req.ResolveFlags,
		LookupFlags:  req.LookupFlags,
		StatMask:     req.StatMask,
		AccessMode:   req.AccessMode,
		AccessFlags:  req.AccessFlags,
		ReadlinkLen:  req.ReadlinkBufferLen,
		Path:         req.RawPath,
	})
	if err != nil {
		return unknownFileLookup(LookupReasonProtocol)
	}

	deadline := time.Now().Add(b.timeout)
	if callerDeadline, hasDeadline := ctx.Deadline(); hasDeadline && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := sendLookupPacket(ctx, fd, wire, deadline); err != nil {
		b.disable()
		if errors.Is(err, context.DeadlineExceeded) {
			return unknownFileLookup(LookupReasonTimeout)
		}
		return unknownFileLookup(LookupReasonProtocol)
	}
	packet, err := receiveLookupPacket(ctx, fd, lookupproto.ResultPacketSize(), deadline)
	if err != nil {
		b.disable()
		if errors.Is(err, context.DeadlineExceeded) {
			return unknownFileLookup(LookupReasonTimeout)
		}
		return unknownFileLookup(LookupReasonProtocol)
	}
	wireResult, err := lookupproto.DecodeResult(packet)
	if err != nil || wireResult.ID != id {
		b.disable()
		return unknownFileLookup(LookupReasonProtocol)
	}
	if err := identity.revalidate(); err != nil {
		return FileLookupResult{Class: LookupStale, Reason: LookupReasonTaskStale}
	}
	return publicLookupResult(wireResult)
}

type pinnedLookupTask struct {
	tid          int
	proc         *os.File
	startTime    uint64
	namespaceTID int
}

func (p *pinnedLookupTask) close() {
	if p != nil && p.proc != nil {
		_ = p.proc.Close()
		p.proc = nil
	}
}

func pinLookupTask(tid int) (*pinnedLookupTask, error) {
	if tid <= 0 {
		return nil, unix.ESRCH
	}
	path := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(tid))
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	p := &pinnedLookupTask{tid: tid, proc: os.NewFile(uintptr(fd), "file-lookup-target-proc")}
	if p.proc == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain lookup target proc directory")
	}
	status, err := readPinnedLookupProcFile(fd, "status", 256*1024)
	if err != nil {
		p.close()
		return nil, err
	}
	p.namespaceTID, err = parseLastNSpid(status)
	if err != nil {
		p.close()
		return nil, err
	}
	p.startTime, err = readPinnedTaskStartTime(fd)
	if err != nil {
		p.close()
		return nil, err
	}
	if err := p.revalidate(); err != nil {
		p.close()
		return nil, err
	}
	return p, nil
}

func (p *pinnedLookupTask) revalidate() error {
	if p == nil || p.proc == nil {
		return unix.ESRCH
	}
	start, err := readPinnedTaskStartTime(int(p.proc.Fd()))
	if err != nil {
		return err
	}
	if start != p.startTime {
		return unix.ESRCH
	}
	status, err := readPinnedLookupProcFile(int(p.proc.Fd()), "status", 256*1024)
	if err != nil {
		return err
	}
	ns, err := parseLastNSpid(status)
	if err != nil || ns != p.namespaceTID {
		return unix.ESRCH
	}
	return nil
}

func readPinnedLookupProcFile(dirfd int, name string, limit int64) ([]byte, error) {
	if name == "" || strings.ContainsRune(name, filepath.Separator) || limit <= 0 {
		return nil, errors.New("invalid pinned proc read")
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "file-lookup-pinned-proc-file")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain pinned proc file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("pinned proc file exceeds bound")
	}
	return data, nil
}

func parseLastNSpid(status []byte) (int, error) {
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
		if len(fields) == 0 {
			break
		}
		value, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || value <= 0 {
			return 0, errors.New("invalid NSpid")
		}
		return value, nil
	}
	return 0, errors.New("missing NSpid")
}

func readPinnedTaskStartTime(dirfd int) (uint64, error) {
	data, err := readPinnedLookupProcFile(dirfd, "stat", 64*1024)
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(data))
	end := strings.LastIndex(line, ")")
	if end < 0 || end+2 >= len(line) {
		return 0, errors.New("malformed task stat")
	}
	fields := strings.Fields(line[end+2:])
	// The suffix starts at field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0, errors.New("task stat omitted start time")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errors.New("invalid task start time")
	}
	return start, nil
}

func fileLookupOperation(syscall int32) (lookupproto.Operation, bool) {
	switch syscall {
	case unix.SYS_OPENAT:
		return lookupproto.OperationOpen, true
	case unix.SYS_OPENAT2:
		return lookupproto.OperationOpenat2, true
	case unix.SYS_STATX:
		return lookupproto.OperationStatx, true
	case unix.SYS_NEWFSTATAT:
		return lookupproto.OperationFstatat, true
	case unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2:
		return lookupproto.OperationFaccessat, true
	case unix.SYS_READLINKAT:
		return lookupproto.OperationReadlinkMetadata, true
	default:
		return legacyFileLookupOperation(syscall)
	}
}

func legacyFileLookupOperation(syscall int32) (lookupproto.Operation, bool) {
	operation := legacySyscallToOperation(syscall, 0)
	switch operation {
	case "open":
		return lookupproto.OperationOpen, true
	case "stat":
		return lookupproto.OperationFstatat, true
	case "access":
		return lookupproto.OperationFaccessat, true
	case "readlink":
		return lookupproto.OperationReadlinkMetadata, true
	default:
		return lookupproto.OperationInvalid, false
	}
}

func publicLookupResult(result lookupproto.Result) FileLookupResult {
	out := FileLookupResult{Errno: result.Errno, Reason: publicLookupReason(result.Reason)}
	switch result.Class {
	case lookupproto.ClassExists:
		out.Class = LookupExists
	case lookupproto.ClassAbsent:
		out.Class = LookupAbsent
	case lookupproto.ClassInaccessible:
		out.Class = LookupInaccessible
	case lookupproto.ClassNotDirectory:
		out.Class = LookupNotDirectory
	case lookupproto.ClassSymlinkLoop:
		out.Class = LookupSymlinkLoop
	case lookupproto.ClassInvalid:
		out.Class = LookupInvalid
	case lookupproto.ClassStale:
		out.Class = LookupStale
	default:
		out.Class = LookupUnknown
	}
	if out.Reason == "" {
		out.Reason = LookupReasonProtocol
		out.Class = LookupUnknown
	}
	return out
}

func publicLookupReason(reason lookupproto.Reason) LookupReason {
	switch reason {
	case lookupproto.ReasonNone:
		return LookupReasonNone
	case lookupproto.ReasonUnavailable:
		return LookupReasonUnavailable
	case lookupproto.ReasonIneligible:
		return LookupReasonIneligible
	case lookupproto.ReasonAdmission:
		return LookupReasonAdmission
	case lookupproto.ReasonTimeout:
		return LookupReasonTimeout
	case lookupproto.ReasonProtocol:
		return LookupReasonProtocol
	case lookupproto.ReasonWorkerCrash:
		return LookupReasonWorkerCrash
	case lookupproto.ReasonWorkerUnavailable:
		return LookupReasonWorkerUnavailable
	case lookupproto.ReasonTaskStale:
		return LookupReasonTaskStale
	case lookupproto.ReasonLineageMismatch:
		return LookupReasonLineageMismatch
	case lookupproto.ReasonNamespaceMismatch:
		return LookupReasonNamespaceMismatch
	case lookupproto.ReasonRootMismatch:
		return LookupReasonRootMismatch
	case lookupproto.ReasonCredentialMismatch:
		return LookupReasonCredentialMismatch
	case lookupproto.ReasonCapabilityMismatch:
		return LookupReasonCapabilityMismatch
	case lookupproto.ReasonSecurityLabel:
		return LookupReasonSecurityLabel
	case lookupproto.ReasonCgroupMismatch:
		return LookupReasonCgroupMismatch
	case lookupproto.ReasonContextUnavailable:
		return LookupReasonContextUnavailable
	case lookupproto.ReasonPIDSensitiveLSM:
		return LookupReasonPIDSensitiveLSM
	case lookupproto.ReasonFUSE:
		return LookupReasonFUSE
	case lookupproto.ReasonMagicLink:
		return LookupReasonMagicLink
	case lookupproto.ReasonDirectoryUnavailable:
		return LookupReasonDirectoryUnavailable
	case lookupproto.ReasonSymlinkContext:
		return LookupReasonSymlinkContext
	case lookupproto.ReasonErrno:
		return LookupReasonErrno
	default:
		return ""
	}
}

func sendLookupPacket(ctx context.Context, fd int, packet []byte, deadline time.Time) error {
	for {
		n, err := unix.SendmsgN(fd, packet, nil, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
		if err == nil {
			if n != len(packet) {
				return io.ErrShortWrite
			}
			return nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err := pollLookupFD(ctx, fd, unix.POLLOUT, deadline); err != nil {
			return err
		}
	}
}

func receiveLookupPacket(ctx context.Context, fd, exactSize int, deadline time.Time) ([]byte, error) {
	if exactSize <= 0 || exactSize > lookupproto.MaxPacketBytes {
		return nil, errors.New("invalid lookup packet size")
	}
	for {
		buf := make([]byte, exactSize)
		n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if err == nil {
			if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != exactSize {
				return nil, errors.New("invalid lookup packet framing")
			}
			return buf, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return nil, err
		}
		if err := pollLookupFD(ctx, fd, unix.POLLIN, deadline); err != nil {
			return nil, err
		}
	}
}

func pollLookupFD(ctx context.Context, fd int, events int16, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		wait := remaining
		if wait > 25*time.Millisecond {
			wait = 25 * time.Millisecond
		}
		milliseconds := int((wait + time.Millisecond - 1) / time.Millisecond)
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(poll, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return io.ErrUnexpectedEOF
		}
		if poll[0].Revents&events != 0 {
			return nil
		}
	}
}
