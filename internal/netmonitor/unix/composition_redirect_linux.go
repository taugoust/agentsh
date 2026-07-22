//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/composition"
	"golang.org/x/sys/unix"
)

// CompositionRedirector replaces an allowed Bubblewrap exec with the trusted
// in-lineage adapter and starts a single broker request channel. The channel is
// capability-safe; successful rewriting is not treated as authentication.
type CompositionRedirector interface {
	Redirect(notifFD int, requestID uint64, ctx ExecveContext, filenamePtr uint64, originalFilenameLen int) error
	Close() error
}

type compositionProcess struct {
	depth int
	token uint64
}

type compositionRedirector struct {
	adapterPath    string
	serve          func(connection *os.File, expectedPID int)
	maxTransitions int
	maxDepth       int

	mu          sync.Mutex
	closed      bool
	transitions int
	nextToken   uint64
	processes   map[int]compositionProcess
	active      sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
	cleanup     func() error
}

func NewCompositionRedirector(adapterPath string, serve func(*os.File, int)) (CompositionRedirector, error) {
	return NewLimitedCompositionRedirector(adapterPath, serve, int(^uint(0)>>1), int(^uint(0)>>1))
}

func NewLimitedCompositionRedirector(adapterPath string, serve func(*os.File, int), maxTransitions, maxDepth int) (CompositionRedirector, error) {
	return NewManagedCompositionRedirector(adapterPath, serve, maxTransitions, maxDepth, nil)
}

func NewManagedCompositionRedirector(adapterPath string, serve func(*os.File, int), maxTransitions, maxDepth int, cleanup func() error) (CompositionRedirector, error) {
	if !filepath.IsAbs(adapterPath) {
		return nil, fmt.Errorf("composition adapter path must be absolute")
	}
	if serve == nil {
		return nil, fmt.Errorf("composition broker callback is required")
	}
	if maxTransitions <= 0 || maxDepth <= 0 {
		return nil, fmt.Errorf("composition transition and depth limits must be positive")
	}
	return &compositionRedirector{
		adapterPath:    adapterPath,
		serve:          serve,
		maxTransitions: maxTransitions,
		maxDepth:       maxDepth,
		processes:      make(map[int]compositionProcess),
		cleanup:        cleanup,
	}, nil
}

func processParent(pid int) (int, error) {
	contents, err := os.ReadFile(filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if value, ok := strings.CutPrefix(line, "PPid:"); ok {
			return strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return 0, fmt.Errorf("process status omitted PPid")
}

func (r *compositionRedirector) beginRedirect() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: composition redirector is closed")
	}
	// Close marks the redirector closed under the same mutex before Wait, so no
	// Add can race with a Wait that has already observed an empty set.
	r.active.Add(1)
	return nil
}

func (r *compositionRedirector) reserveTransition(pid int) (compositionProcess, error) {
	depth := 1
	ancestor := pid
	for steps := 0; steps < 256; steps++ {
		parent, err := processParent(ancestor)
		if err != nil || parent <= 0 || parent == ancestor {
			break
		}
		r.mu.Lock()
		entry, found := r.processes[parent]
		r.mu.Unlock()
		if found {
			depth = entry.depth + 1
			break
		}
		ancestor = parent
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return compositionProcess{}, fmt.Errorf("E_COMPOSITION_BACKEND_UNAVAILABLE: composition redirector is closed")
	}
	if r.transitions >= r.maxTransitions {
		return compositionProcess{}, fmt.Errorf("E_COMPOSITION_LIMIT_EXCEEDED: namespace transition limit %d reached", r.maxTransitions)
	}
	if depth > r.maxDepth {
		return compositionProcess{}, fmt.Errorf("E_COMPOSITION_LIMIT_EXCEEDED: namespace depth %d exceeds maximum %d", depth, r.maxDepth)
	}
	r.transitions++
	r.nextToken++
	return compositionProcess{depth: depth, token: r.nextToken}, nil
}

func (r *compositionRedirector) trackProcess(pid int, entry compositionProcess) {
	r.mu.Lock()
	r.processes[pid] = entry
	r.mu.Unlock()
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		r.mu.Lock()
		if current, ok := r.processes[pid]; ok && current.token == entry.token {
			delete(r.processes, pid)
		}
		r.mu.Unlock()
		return
	}
	go func() {
		defer unix.Close(pidfd)
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		for {
			if _, err := unix.Poll(poll, -1); err == unix.EINTR {
				continue
			}
			break
		}
		r.mu.Lock()
		if current, ok := r.processes[pid]; ok && current.token == entry.token {
			delete(r.processes, pid)
		}
		r.mu.Unlock()
	}()
}

func (r *compositionRedirector) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		r.active.Wait()
		if r.cleanup != nil {
			r.closeErr = r.cleanup()
		}
	})
	return r.closeErr
}

func (r *compositionRedirector) Redirect(notifFD int, requestID uint64, ctx ExecveContext, filenamePtr uint64, originalFilenameLen int) error {
	if filenamePtr == 0 {
		return fmt.Errorf("composition requires execve with a pathname")
	}
	fdPath := filepath.Join(string(filepath.Separator), "proc", "self", "fd", strconv.Itoa(composition.AdapterFD))
	if len(fdPath) > originalFilenameLen {
		return fmt.Errorf("composition adapter fd path does not fit exec pathname buffer")
	}
	if err := NotifIDValid(notifFD, requestID); err != nil {
		return fmt.Errorf("composition notification expired: %w", err)
	}
	if err := r.beginRedirect(); err != nil {
		return err
	}
	redirectActive := true
	defer func() {
		if redirectActive {
			r.active.Done()
		}
	}()
	transition, err := r.reserveTransition(ctx.PID)
	if err != nil {
		return err
	}

	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create composition socketpair: %w", err)
	}
	server := os.NewFile(uintptr(sockets[0]), "agentsh-composition-server")
	clientFD := sockets[1]
	closeAll := true
	defer func() {
		if closeAll {
			_ = server.Close()
		}
		_ = unix.Close(clientFD)
	}()
	if err := unix.SetsockoptInt(int(server.Fd()), unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return fmt.Errorf("enable composition sender credentials: %w", err)
	}
	adapterFD, err := unix.Open(r.adapterPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open composition adapter: %w", err)
	}
	defer unix.Close(adapterFD)

	if _, err := NotifAddFD(notifFD, requestID, clientFD, composition.InjectFD, SECCOMP_ADDFD_FLAG_SETFD); err != nil {
		return fmt.Errorf("inject composition channel: %w", err)
	}
	if _, err := NotifAddFD(notifFD, requestID, adapterFD, composition.AdapterFD, SECCOMP_ADDFD_FLAG_SETFD); err != nil {
		return fmt.Errorf("inject composition adapter: %w", err)
	}
	if err := writeString(ctx.PID, filenamePtr, fdPath); err != nil {
		return fmt.Errorf("rewrite Bubblewrap exec to composition adapter: %w", err)
	}
	if err := NotifIDValid(notifFD, requestID); err != nil {
		return fmt.Errorf("composition notification changed before release: %w", err)
	}

	closeAll = false
	_ = unix.Close(clientFD)
	clientFD = -1
	r.trackProcess(ctx.PID, transition)
	redirectActive = false
	go func() {
		defer r.active.Done()
		r.serve(server, ctx.PID)
	}()
	return nil
}
