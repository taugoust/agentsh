//go:build linux && cgo

package unix

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/composition"
	"golang.org/x/sys/unix"
)

const maxCompositionPathMappings = 4096

type compositionPathState struct {
	aliases   []composition.PathAlias
	symlinks  []composition.PathSymlink
	token     uint64
	pidfd     int
	ownerPID  int
	namespace string
	stop      chan struct{}
	done      chan struct{}
	stopOnce  sync.Once
}

func (s *compositionPathState) stopAndWait() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
}

// CompositionPathRegistry binds the broker's final mount-plan attribution to a
// live mount namespace. File policy can then evaluate both the visible path and
// the original source spelling even after bind aliases and plan-created
// symlinks. Possessing or registering mappings grants no filesystem authority.
type CompositionPathRegistry struct {
	mu        sync.RWMutex
	closed    bool
	nextToken uint64
	states    map[string]*compositionPathState
}

func NewCompositionPathRegistry() *CompositionPathRegistry {
	return &CompositionPathRegistry{states: make(map[string]*compositionPathState)}
}

func mountNamespaceIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid mount namespace pid %d", pid)
	}
	procPath := filepath.Join(string(filepath.Separator), "proc", strconv.Itoa(pid))
	procFD, err := unix.Open(procPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(procFD)
	buffer := make([]byte, 128)
	length, err := unix.Readlinkat(procFD, filepath.Join("ns", "mnt"), buffer)
	if err != nil {
		return "", err
	}
	identity := string(buffer[:length])
	if !strings.HasPrefix(identity, "mnt:[") || !strings.HasSuffix(identity, "]") {
		return "", fmt.Errorf("invalid mount namespace identity %q", identity)
	}
	return identity, nil
}

func cleanCompositionMappingPath(path string, allowRelative bool) (string, error) {
	if path == "" {
		return "", nil
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("composition path contains NUL")
	}
	if !filepath.IsAbs(path) {
		if allowRelative && filepath.Clean(path) == path {
			return path, nil
		}
		return "", fmt.Errorf("composition path is not absolute: %q", path)
	}
	if filepath.Clean(path) != path {
		return "", fmt.Errorf("composition path is not clean: %q", path)
	}
	return path, nil
}

func pathAtOrBelow(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func replacePathPrefix(path, target, source string) (string, bool) {
	if !pathAtOrBelow(path, target) {
		return path, false
	}
	relative, err := filepath.Rel(target, path)
	if err != nil {
		return path, false
	}
	if !filepath.IsAbs(source) {
		source = filepath.Join(filepath.Dir(target), source)
	}
	if relative == "." {
		return filepath.Clean(source), true
	}
	return filepath.Join(source, relative), true
}

// CompositionPathResolution describes how one path in a composed mount
// namespace maps back to the outer namespace. Fresh is true for a path backed
// by a broker-created filesystem rather than a host bind. FreshWritable is the
// narrower subset backed by a broker-provisioned writable tmpfs.
type CompositionPathResolution struct {
	Path          string
	Covered       bool
	Fresh         bool
	FreshWritable bool
}

func normalizeCompositionPath(state *compositionPathState, path string) (CompositionPathResolution, error) {
	if path == "" || !filepath.IsAbs(path) {
		return CompositionPathResolution{Path: path}, nil
	}
	path = filepath.Clean(path)
	if state == nil {
		return CompositionPathResolution{Path: path}, nil
	}

	// Resolve only symlinks created by the reviewed plan. Source-tree symlinks
	// remain represented by their original source spelling, exactly as they were
	// under the outer file policy.
	seen := make(map[string]struct{})
	for depth := 0; depth < 40; depth++ {
		if _, duplicate := seen[path]; duplicate {
			return CompositionPathResolution{}, errors.New("composition symlink attribution loop")
		}
		seen[path] = struct{}{}
		rewritten := false
		for _, symlink := range state.symlinks {
			if next, matched := replacePathPrefix(path, symlink.Target, symlink.Source); matched {
				path = next
				rewritten = true
				break
			}
		}
		if !rewritten {
			break
		}
		if depth == 39 {
			return CompositionPathResolution{}, errors.New("composition symlink attribution depth exceeded")
		}
	}

	for _, alias := range state.aliases {
		if !pathAtOrBelow(path, alias.Target) {
			continue
		}
		if alias.Source == "" {
			return CompositionPathResolution{
				Path:          path,
				Covered:       true,
				Fresh:         true,
				FreshWritable: alias.FreshWritable,
			}, nil
		}
		mapped, _ := replacePathPrefix(path, alias.Target, alias.Source)
		return CompositionPathResolution{Path: mapped, Covered: true}, nil
	}
	return CompositionPathResolution{Path: path}, nil
}

func (r *CompositionPathRegistry) stateForPID(pid int) (*compositionPathState, error) {
	if r == nil {
		return nil, nil
	}
	namespace, err := mountNamespaceIdentity(pid)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	state := r.states[namespace]
	r.mu.RUnlock()
	return state, nil
}

// ResolveDetails returns complete source-attribution information for a path in
// a composed mount namespace.
func (r *CompositionPathRegistry) ResolveDetails(pid int, path string) (CompositionPathResolution, error) {
	state, err := r.stateForPID(pid)
	if err != nil {
		return CompositionPathResolution{}, err
	}
	return normalizeCompositionPath(state, path)
}

// Resolve returns the source-attributed spelling for path and whether the path
// lies below a composed mount/symlink boundary. An unchanged path with
// covered=true is a fresh-filesystem barrier or identity bind.
func (r *CompositionPathRegistry) Resolve(pid int, path string) (string, bool, error) {
	resolution, err := r.ResolveDetails(pid, path)
	if err != nil {
		return "", false, err
	}
	return resolution.Path, resolution.Covered, nil
}

// Register publishes one post-pivot snapshot. Sources are first normalized
// through the parent composition namespace, which preserves attribution across
// recursively nested Bubblewrap invocations.
func (r *CompositionPathRegistry) Register(parentPID, targetPID int, mappings composition.PathMappings) error {
	if r == nil {
		return errors.New("composition path registry is nil")
	}
	if len(mappings.Aliases) == 0 || len(mappings.Aliases)+len(mappings.Symlinks) > maxCompositionPathMappings {
		return fmt.Errorf("invalid composition path mapping count aliases=%d symlinks=%d", len(mappings.Aliases), len(mappings.Symlinks))
	}

	parentState, err := r.stateForPID(parentPID)
	if err != nil {
		return fmt.Errorf("read parent composition namespace: %w", err)
	}
	aliases := make([]composition.PathAlias, 0, len(mappings.Aliases))
	seenAliases := make(map[string]struct{}, len(mappings.Aliases))
	rootBarrier := false
	for _, alias := range mappings.Aliases {
		target, err := cleanCompositionMappingPath(alias.Target, false)
		if err != nil {
			return err
		}
		if _, duplicate := seenAliases[target]; duplicate {
			return fmt.Errorf("duplicate composition alias target %q", target)
		}
		seenAliases[target] = struct{}{}
		source, err := cleanCompositionMappingPath(alias.Source, false)
		if err != nil {
			return err
		}
		freshWritable := alias.FreshWritable
		if source != "" && freshWritable {
			return fmt.Errorf("composition alias %q cannot be both source-backed and fresh-writable", target)
		}
		if source != "" {
			parentResolution, err := normalizeCompositionPath(parentState, source)
			if err != nil {
				return fmt.Errorf("normalize parent composition source %q: %w", alias.Source, err)
			}
			if parentResolution.FreshWritable {
				// A bind sourced from a parent composition's writable tmpfs
				// remains private synthetic state in the nested namespace.
				source = ""
				freshWritable = true
			} else {
				// Preserve a source spelling behind the read-only synthetic root.
				// Besides keeping source policy effective, this distinguishes an
				// atomic replacement snapshot from a nested writable tmpfs bind.
				source = parentResolution.Path
			}
		}
		if target == string(filepath.Separator) && source == "" {
			if freshWritable {
				return errors.New("composition synthetic-root barrier cannot be fresh-writable")
			}
			rootBarrier = true
		}
		aliases = append(aliases, composition.PathAlias{
			Target: target, Source: source, FreshWritable: freshWritable,
		})
	}
	if !rootBarrier {
		return errors.New("composition path mappings omit the synthetic-root barrier")
	}

	symlinks := make([]composition.PathSymlink, 0, len(mappings.Symlinks))
	seenSymlinks := make(map[string]struct{}, len(mappings.Symlinks))
	for _, symlink := range mappings.Symlinks {
		target, err := cleanCompositionMappingPath(symlink.Target, false)
		if err != nil {
			return err
		}
		source, err := cleanCompositionMappingPath(symlink.Source, true)
		if err != nil || source == "" {
			return fmt.Errorf("invalid composition symlink source %q: %v", symlink.Source, err)
		}
		if _, duplicate := seenSymlinks[target]; duplicate {
			return fmt.Errorf("duplicate composition symlink target %q", target)
		}
		seenSymlinks[target] = struct{}{}
		symlinks = append(symlinks, composition.PathSymlink{Target: target, Source: source})
	}

	// Longest-prefix first makes lookup deterministic and prevents a root or
	// parent mapping from shadowing a more specific bind/fresh mount.
	sort.Slice(aliases, func(i, j int) bool {
		if len(aliases[i].Target) == len(aliases[j].Target) {
			return aliases[i].Target < aliases[j].Target
		}
		return len(aliases[i].Target) > len(aliases[j].Target)
	})
	sort.Slice(symlinks, func(i, j int) bool {
		if len(symlinks[i].Target) == len(symlinks[j].Target) {
			return symlinks[i].Target < symlinks[j].Target
		}
		return len(symlinks[i].Target) > len(symlinks[j].Target)
	})

	pidfd, err := unix.PidfdOpen(targetPID, 0)
	if err != nil {
		return fmt.Errorf("pin composition path mapping owner: %w", err)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.Signal(0), nil, 0); err != nil {
		_ = unix.Close(pidfd)
		return fmt.Errorf("composition path mapping owner exited: %w", err)
	}
	namespace, err := mountNamespaceIdentity(targetPID)
	if err != nil {
		_ = unix.Close(pidfd)
		return fmt.Errorf("read target composition namespace: %w", err)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.Signal(0), nil, 0); err != nil {
		_ = unix.Close(pidfd)
		return fmt.Errorf("composition path mapping owner exited while pinning namespace: %w", err)
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = unix.Close(pidfd)
		return errors.New("composition path registry is closed")
	}
	r.nextToken++
	state := &compositionPathState{
		aliases: aliases, symlinks: symlinks, token: r.nextToken,
		pidfd: pidfd, ownerPID: targetPID, namespace: namespace,
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	previous := r.states[namespace]
	r.states[namespace] = state
	r.mu.Unlock()
	go r.removeAfterExit(state)
	if previous != nil {
		previous.stopAndWait()
	}
	return nil
}

func (r *CompositionPathRegistry) removeAfterExit(state *compositionPathState) {
	defer close(state.done)
	defer unix.Close(state.pidfd)
	poll := []unix.PollFd{{Fd: int32(state.pidfd), Events: unix.POLLIN}}
	for {
		select {
		case <-state.stop:
			return
		default:
		}
		ready, err := unix.Poll(poll, 25)
		if err == unix.EINTR {
			continue
		}
		if err != nil || ready > 0 {
			break
		}
	}
	r.mu.Lock()
	if current := r.states[state.namespace]; current != nil && current.token == state.token {
		delete(r.states, state.namespace)
	}
	r.mu.Unlock()
}

func (r *CompositionPathRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	states := make([]*compositionPathState, 0, len(r.states))
	for _, state := range r.states {
		states = append(states, state)
	}
	r.states = make(map[string]*compositionPathState)
	r.mu.Unlock()
	for _, state := range states {
		state.stopOnce.Do(func() { close(state.stop) })
	}
	for _, state := range states {
		<-state.done
	}
	return nil
}
