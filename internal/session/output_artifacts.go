package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/workspace/cleanup"
)

const outputArtifactDirName = "output-artifacts"

var (
	ErrOutputArtifactsUnavailable = errors.New("session output artifacts are unavailable")
	ErrOutputArtifactNotFound     = errors.New("output artifact is not registered for this session")
)

// OutputArtifact describes a bounded, session-owned artifact. Path is an exact
// host path that may be passed back to the session read_file endpoint.
type OutputArtifact struct {
	Path         string
	BytesWritten int64
	TotalBytes   int64
	Truncated    bool
}

type outputArtifactRegistration struct {
	info os.FileInfo
}

// OutputArtifactWriter incrementally writes one bounded session artifact. It is
// safe for concurrent writes, allowing stdout and stderr to share a file while
// preserving the order in which writes reach the server.
type OutputArtifactWriter struct {
	mu       sync.Mutex
	session  *Session
	file     *os.File
	path     string
	maxBytes int64
	written  int64
	total    int64
	closed   bool
	writeErr error
}

// ConfigureOutputArtifacts sets the per-artifact write bound for the session.
func (s *Session) ConfigureOutputArtifacts(maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("output artifact max bytes must be > 0")
	}
	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	s.outputArtifactMaxBytes = maxBytes
	return nil
}

// NewOutputArtifactWriter creates an unregistered private artifact. The path is
// registered only after Finish succeeds, so partial or failed files cannot be
// read through the trusted read_file capability.
func (s *Session) NewOutputArtifactWriter(name string) (*OutputArtifactWriter, error) {
	runtimeTmp := s.RuntimeTmpPath()
	if runtimeTmp == "" || !filepath.IsAbs(runtimeTmp) {
		return nil, fmt.Errorf("%w: RuntimeTmp is not an absolute path", ErrOutputArtifactsUnavailable)
	}
	runtimeTmp = filepath.Clean(runtimeTmp)

	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	if s.outputArtifactsClosed {
		return nil, ErrOutputArtifactsUnavailable
	}
	if s.outputArtifactMaxBytes <= 0 {
		return nil, fmt.Errorf("%w: max bytes is not configured", ErrOutputArtifactsUnavailable)
	}

	info, err := os.Stat(runtimeTmp)
	if err != nil {
		return nil, fmt.Errorf("stat session RuntimeTmp: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: RuntimeTmp is not a directory", ErrOutputArtifactsUnavailable)
	}

	root := filepath.Join(runtimeTmp, outputArtifactDirName)
	if !IsRealPathUnder(root, runtimeTmp) {
		return nil, fmt.Errorf("%w: artifact root escapes RuntimeTmp", ErrOutputArtifactsUnavailable)
	}
	if err := ensurePrivateArtifactDir(root); err != nil {
		return nil, err
	}
	s.outputArtifactRoot = root

	file, err := os.CreateTemp(root, outputArtifactPrefix(name)+"-*")
	if err != nil {
		return nil, fmt.Errorf("create output artifact: %w", err)
	}
	path := filepath.Clean(file.Name())
	if !IsRealPathUnder(path, root) {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, errors.New("created output artifact escapes artifact root")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod output artifact: %w", err)
	}

	return &OutputArtifactWriter{
		session:  s,
		file:     file,
		path:     path,
		maxBytes: s.outputArtifactMaxBytes,
	}, nil
}

// Write counts every source byte while retaining no more than the configured
// artifact limit. Once the bound is reached, subsequent bytes are deliberately
// discarded while TotalBytes continues to advance.
func (w *OutputArtifactWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("output artifact writer is closed")
	}
	if len(p) == 0 {
		return 0, nil
	}
	w.total += int64(len(p))
	if w.writeErr != nil || w.written >= w.maxBytes {
		return len(p), w.writeErr
	}
	remaining := w.maxBytes - w.written
	data := p
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	n, err := w.file.Write(data)
	w.written += int64(n)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.writeErr = err
		return len(p), err
	}
	return len(p), nil
}

// Finish closes and registers the artifact. A failed writer is removed and
// never exposed as a readable capability.
func (w *OutputArtifactWriter) Finish() (OutputArtifact, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return OutputArtifact{}, errors.New("output artifact writer is closed")
	}
	w.closed = true
	artifact := OutputArtifact{
		Path:         w.path,
		BytesWritten: w.written,
		TotalBytes:   w.total,
		Truncated:    w.total > w.written,
	}
	if w.writeErr != nil {
		_ = w.file.Close()
		_ = os.Remove(w.path)
		return OutputArtifact{}, fmt.Errorf("write output artifact: %w", w.writeErr)
	}
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		_ = os.Remove(w.path)
		return OutputArtifact{}, fmt.Errorf("sync output artifact: %w", err)
	}
	fileInfo, err := w.file.Stat()
	if err != nil {
		_ = w.file.Close()
		_ = os.Remove(w.path)
		return OutputArtifact{}, fmt.Errorf("stat output artifact: %w", err)
	}
	if !fileInfo.Mode().IsRegular() {
		_ = w.file.Close()
		_ = os.Remove(w.path)
		return OutputArtifact{}, errors.New("output artifact is not a regular file")
	}
	if err := w.file.Close(); err != nil {
		_ = os.Remove(w.path)
		return OutputArtifact{}, fmt.Errorf("close output artifact: %w", err)
	}

	s := w.session
	s.outputArtifactsMu.Lock()
	if s.outputArtifactsClosed {
		s.outputArtifactsMu.Unlock()
		_ = os.Remove(w.path)
		return OutputArtifact{}, ErrOutputArtifactsUnavailable
	}
	if s.outputArtifacts == nil {
		s.outputArtifacts = make(map[string]outputArtifactRegistration)
	}
	s.outputArtifacts[w.path] = outputArtifactRegistration{info: fileInfo}
	paths := s.outputArtifactPathsLocked()
	hook := s.outputArtifactsChanged
	s.outputArtifactsMu.Unlock()
	if hook != nil {
		hook(paths)
	}
	return artifact, nil
}

// Abort closes and removes an unfinished artifact.
func (w *OutputArtifactWriter) Abort() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	closeErr := w.file.Close()
	removeErr := os.Remove(w.path)
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}

// WriteOutputArtifact writes a finite source through the incremental writer.
// It reads at most one byte beyond the configured cap, which is enough to mark
// the artifact incomplete without consuming an unbounded reader.
func (s *Session) WriteOutputArtifact(name string, src io.Reader) (OutputArtifact, error) {
	if src == nil {
		return OutputArtifact{}, errors.New("output artifact source is nil")
	}
	writer, err := s.NewOutputArtifactWriter(name)
	if err != nil {
		return OutputArtifact{}, err
	}
	limit := writer.maxBytes + 1
	if _, err := io.Copy(writer, io.LimitReader(src, limit)); err != nil {
		_ = writer.Abort()
		return OutputArtifact{}, fmt.Errorf("write output artifact: %w", err)
	}
	return writer.Finish()
}

// RegisteredOutputArtifactPath resolves only an exact path previously created
// and registered by this session. It intentionally does not accept directories,
// relative paths, prefixes, or arbitrary files elsewhere in RuntimeTmp.
func (s *Session) RegisteredOutputArtifactPath(path string) (string, bool) {
	candidate, ok := normalizeOutputArtifactPath(path)
	if !ok {
		return "", false
	}
	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	if s.outputArtifactsClosed {
		return "", false
	}
	_, ok = s.outputArtifacts[candidate]
	return candidate, ok
}

// OpenOutputArtifact opens a registered artifact and verifies that its file
// identity has not changed since registration. This rejects symlink or hardlink
// replacement without relying solely on a path-prefix check.
func (s *Session) OpenOutputArtifact(path string) (*os.File, os.FileInfo, error) {
	candidate, ok := normalizeOutputArtifactPath(path)
	if !ok {
		return nil, nil, ErrOutputArtifactNotFound
	}

	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	registration, ok := s.outputArtifacts[candidate]
	if !ok || s.outputArtifactsClosed {
		return nil, nil, ErrOutputArtifactNotFound
	}
	pathInfo, err := os.Lstat(candidate)
	if err != nil {
		return nil, nil, err
	}
	if !pathInfo.Mode().IsRegular() || !os.SameFile(registration.info, pathInfo) {
		return nil, nil, errors.New("registered output artifact identity changed")
	}
	file, err := os.Open(candidate)
	if err != nil {
		return nil, nil, err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !fileInfo.Mode().IsRegular() || !os.SameFile(registration.info, fileInfo) {
		_ = file.Close()
		return nil, nil, errors.New("registered output artifact identity changed")
	}
	return file, fileInfo, nil
}

func (s *Session) SetOutputArtifactPersistenceHook(hook func([]string)) {
	s.outputArtifactsMu.Lock()
	s.outputArtifactsChanged = hook
	paths := s.outputArtifactPathsLocked()
	s.outputArtifactsMu.Unlock()
	if hook != nil {
		hook(paths)
	}
}

func (s *Session) RestoreOutputArtifacts(paths []string) error {
	runtimeTmp := filepath.Clean(s.RuntimeTmpPath())
	if runtimeTmp == "." || !filepath.IsAbs(runtimeTmp) {
		return ErrOutputArtifactsUnavailable
	}
	root := filepath.Join(runtimeTmp, outputArtifactDirName)
	registrations := make(map[string]outputArtifactRegistration, len(paths))
	for _, path := range paths {
		candidate, ok := normalizeOutputArtifactPath(path)
		if !ok || !IsRealPathUnder(candidate, root) || filepath.Dir(candidate) != root {
			return fmt.Errorf("restore output artifact outside exact session root")
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			return fmt.Errorf("restore output artifact %s: %w", candidate, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("restore output artifact %s: invalid file type or permissions", candidate)
		}
		registrations[candidate] = outputArtifactRegistration{info: info}
	}
	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	if s.outputArtifactsClosed {
		return ErrOutputArtifactsUnavailable
	}
	s.outputArtifactRoot = root
	s.outputArtifacts = registrations
	return nil
}

func (s *Session) outputArtifactPathsLocked() []string {
	paths := make([]string, 0, len(s.outputArtifacts))
	for path := range s.outputArtifacts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func normalizeOutputArtifactPath(path string) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	candidate := filepath.Clean(filepath.FromSlash(path))
	if !filepath.IsAbs(candidate) {
		return "", false
	}
	return candidate, true
}

func outputArtifactPrefix(name string) string {
	name = strings.TrimSpace(name)
	var prefix strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			prefix.WriteRune(r)
		default:
			prefix.WriteByte('-')
		}
	}
	clean := strings.Trim(prefix.String(), ".-")
	if clean == "" {
		return "artifact"
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}

func ensurePrivateArtifactDir(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create output artifact directory: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("stat output artifact directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output artifact root is not a directory")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("chmod output artifact directory: %w", err)
	}
	return nil
}

func (s *Session) resetOutputArtifactRuntime() {
	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	s.outputArtifacts = nil
	s.outputArtifactRoot = ""
	s.outputArtifactsClosed = false
}

func (s *Session) closeOutputArtifacts() error {
	s.outputArtifactsMu.Lock()
	defer s.outputArtifactsMu.Unlock()
	root := s.outputArtifactRoot
	s.outputArtifacts = nil
	s.outputArtifactsClosed = true
	if root == "" {
		return nil
	}
	if err := cleanup.RemoveAllWritable(root); err != nil {
		// Retain the root so a later CloseRuntime call can retry cleanup.
		return fmt.Errorf("remove output artifacts: %w", err)
	}
	s.outputArtifactRoot = ""
	return nil
}
