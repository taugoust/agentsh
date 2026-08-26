//go:build linux

package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	SchemaVersion      = 1
	MediaTypeGitBundle = "application/vnd.git.bundle"

	KindGitInputBundle  Kind = "git-input-bundle"
	KindGitResultBundle Kind = "git-result-bundle"

	artifactDirName    = "artifacts"
	maxDescriptorBytes = 64 << 10
)

var (
	ErrInvalid  = errors.New("invalid runtime artifact")
	ErrNotFound = errors.New("runtime artifact not found")
	ErrTooLarge = errors.New("runtime artifact exceeds its size limit")
	ErrCorrupt  = errors.New("runtime artifact integrity check failed")
)

type Kind string

type Descriptor struct {
	SchemaVersion int       `json:"schema_version"`
	ArtifactID    string    `json:"artifact_id"`
	SessionID     string    `json:"session_id"`
	Kind          Kind      `json:"kind"`
	MediaType     string    `json:"media_type"`
	SHA256        string    `json:"sha256"`
	Size          int64     `json:"size"`
	Complete      bool      `json:"complete"`
	CreatedAt     time.Time `json:"created_at"`
}

type Store struct {
	stateDir  string
	sessionID string
	root      string
	maxBytes  int64
}

func NewStore(stateDir, sessionID string, maxBytes int64) (*Store, error) {
	if !validName(sessionID) || filepath.Base(sessionID) != sessionID {
		return nil, fmt.Errorf("%w: invalid session identity", ErrInvalid)
	}
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir || filepath.Base(stateDir) != sessionID {
		return nil, fmt.Errorf("%w: state directory is not bound to the exact session", ErrInvalid)
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: size limit must be positive", ErrInvalid)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return nil, fmt.Errorf("stat runtime artifact state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: state directory is not a direct directory", ErrInvalid)
	}
	store := &Store{
		stateDir:  stateDir,
		sessionID: sessionID,
		root:      filepath.Join(stateDir, "runtime", artifactDirName),
		maxBytes:  maxBytes,
	}
	if err := store.ensureRoot(); err != nil {
		return nil, err
	}
	unlock, err := store.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := store.reconcileLocked(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Put(ctx context.Context, kind Kind, source io.Reader) (Descriptor, error) {
	if err := validateKind(kind); err != nil {
		return Descriptor{}, err
	}
	if source == nil {
		return Descriptor{}, fmt.Errorf("%w: source is nil", ErrInvalid)
	}
	if err := s.ensureRoot(); err != nil {
		return Descriptor{}, err
	}
	unlock, err := s.lock()
	if err != nil {
		return Descriptor{}, err
	}
	defer unlock()
	id := uuid.NewString()
	temporary, err := os.OpenFile(filepath.Join(s.root, ".tmp-"+id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Descriptor{}, fmt.Errorf("create runtime artifact: %w", err)
	}
	temporaryPath := temporary.Name()
	publishedPath := s.dataPath(id)
	published := false
	defer func() {
		if !published {
			_ = os.Remove(temporaryPath)
			_ = os.Remove(publishedPath)
		}
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(temporary, hasher)
	written, copyErr := copyBounded(ctx, writer, source, s.maxBytes)
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return Descriptor{}, err
	}
	if err := os.Rename(temporaryPath, publishedPath); err != nil {
		return Descriptor{}, fmt.Errorf("publish runtime artifact content: %w", err)
	}
	if err := syncDirectory(s.root); err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		SchemaVersion: SchemaVersion,
		ArtifactID:    id,
		SessionID:     s.sessionID,
		Kind:          kind,
		MediaType:     MediaTypeGitBundle,
		SHA256:        "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Size:          written,
		Complete:      true,
		CreatedAt:     time.Now().UTC(),
	}
	descriptorPublished, err := s.writeDescriptor(descriptor)
	if descriptorPublished {
		// Once the descriptor rename commits, the artifact is discoverable and
		// must survive an ambiguous directory-sync result for reconciliation.
		published = true
	}
	if err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

func (s *Store) Open(ctx context.Context, artifactID string, expectedKind Kind) (*os.File, Descriptor, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, Descriptor{}, err
	}
	defer unlock()
	if err := validateArtifactID(artifactID); err != nil {
		return nil, Descriptor{}, err
	}
	if err := validateKind(expectedKind); err != nil {
		return nil, Descriptor{}, err
	}
	descriptor, err := s.readDescriptor(artifactID)
	if err != nil {
		return nil, Descriptor{}, err
	}
	if descriptor.SessionID != s.sessionID || descriptor.Kind != expectedKind {
		return nil, Descriptor{}, fmt.Errorf("%w: artifact identity or kind mismatch", ErrInvalid)
	}
	path := s.dataPath(artifactID)
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, Descriptor{}, ErrCorrupt
	}
	if err != nil {
		return nil, Descriptor{}, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o077 != 0 {
		return nil, Descriptor{}, fmt.Errorf("%w: content is not a private regular file", ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, Descriptor{}, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, Descriptor{}, fmt.Errorf("%w: content identity changed while opening", ErrCorrupt)
	}
	hasher := sha256.New()
	size, hashErr := copyBounded(ctx, hasher, file, s.maxBytes)
	if hashErr != nil || size != descriptor.Size || "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != descriptor.SHA256 {
		_ = file.Close()
		if hashErr != nil {
			if errors.Is(hashErr, context.Canceled) || errors.Is(hashErr, context.DeadlineExceeded) {
				return nil, Descriptor{}, hashErr
			}
			return nil, Descriptor{}, fmt.Errorf("%w: %v", ErrCorrupt, hashErr)
		}
		return nil, Descriptor{}, ErrCorrupt
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, Descriptor{}, err
	}
	return file, descriptor, nil
}

func (s *Store) List() ([]Descriptor, error) {
	if err := s.ensureRoot(); err != nil {
		return nil, err
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	out := make([]Descriptor, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if err := validateArtifactID(id); err != nil {
			return nil, fmt.Errorf("%w: unexpected artifact descriptor %s", ErrInvalid, name)
		}
		descriptor, err := s.readDescriptor(id)
		if err != nil {
			return nil, err
		}
		out = append(out, descriptor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ArtifactID < out[j].ArtifactID })
	return out, nil
}

func (s *Store) Delete(artifactID string, expectedKind Kind) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := validateArtifactID(artifactID); err != nil {
		return err
	}
	if err := validateKind(expectedKind); err != nil {
		return err
	}
	descriptor, err := s.readDescriptor(artifactID)
	if errors.Is(err, ErrNotFound) {
		return s.finishDeleteLocked(artifactID)
	}
	if err != nil {
		return err
	}
	if descriptor.SessionID != s.sessionID || descriptor.Kind != expectedKind {
		return fmt.Errorf("%w: artifact identity or kind mismatch", ErrInvalid)
	}
	if err := os.Rename(s.descriptorPath(artifactID), s.tombstonePath(artifactID)); err != nil {
		return err
	}
	if err := syncDirectory(s.root); err != nil {
		return err
	}
	return s.finishDeleteLocked(artifactID)
}

func (s *Store) finishDeleteLocked(artifactID string) error {
	tombstone := s.tombstonePath(artifactID)
	if _, err := os.Lstat(tombstone); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.Remove(s.dataPath(artifactID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(tombstone); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.root)
}

func (s *Store) lock() (func(), error) {
	fd, err := unix.Open(filepath.Join(s.root, ".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runtime artifact lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lock runtime artifacts: %w", err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func (s *Store) reconcileLocked() error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	descriptors := make(map[string]struct{})
	bundles := make(map[string]struct{})
	deleting := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == ".lock":
		case strings.HasPrefix(name, ".tmp-"):
			if entry.IsDir() {
				return fmt.Errorf("%w: artifact temporary path is a directory", ErrInvalid)
			}
			if err := os.Remove(filepath.Join(s.root, name)); err != nil {
				return err
			}
		case strings.HasPrefix(name, ".delete-") && strings.HasSuffix(name, ".json"):
			id := strings.TrimSuffix(strings.TrimPrefix(name, ".delete-"), ".json")
			if err := validateArtifactID(id); err != nil {
				return err
			}
			if err := s.finishDeleteLocked(id); err != nil {
				return err
			}
			deleting[id] = struct{}{}
		case strings.HasSuffix(name, ".json"):
			id := strings.TrimSuffix(name, ".json")
			if err := validateArtifactID(id); err != nil {
				return err
			}
			descriptors[id] = struct{}{}
		case strings.HasSuffix(name, ".bundle"):
			id := strings.TrimSuffix(name, ".bundle")
			if err := validateArtifactID(id); err != nil {
				return err
			}
			if _, isDeleting := deleting[id]; !isDeleting {
				bundles[id] = struct{}{}
			}
		default:
			return fmt.Errorf("%w: unexpected artifact path %s", ErrInvalid, name)
		}
	}
	for id := range descriptors {
		if _, ok := bundles[id]; !ok {
			return fmt.Errorf("%w: descriptor %s has no content", ErrCorrupt, id)
		}
		if _, err := s.readDescriptor(id); err != nil {
			return err
		}
	}
	for id := range bundles {
		if _, ok := descriptors[id]; ok {
			continue
		}
		if err := os.Remove(s.dataPath(id)); err != nil {
			return err
		}
	}
	return syncDirectory(s.root)
}

func (s *Store) ensureRoot() error {
	runtimeDir := filepath.Dir(s.root)
	for _, directory := range []string{runtimeDir, s.root} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create runtime artifact directory: %w", err)
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: artifact path component is not a direct directory", ErrInvalid)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	if err := syncDirectory(s.stateDir); err != nil {
		return err
	}
	return syncDirectory(runtimeDir)
}

func (s *Store) writeDescriptor(descriptor Descriptor) (bool, error) {
	if err := descriptor.Validate(); err != nil {
		return false, err
	}
	data, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return false, err
	}
	file, err := os.CreateTemp(s.root, ".tmp-descriptor-")
	if err != nil {
		return false, err
	}
	temporary := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return false, err
	}
	_, writeErr := file.Write(append(data, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return false, err
	}
	if err := os.Rename(temporary, s.descriptorPath(descriptor.ArtifactID)); err != nil {
		_ = os.Remove(temporary)
		return false, err
	}
	return true, syncDirectory(s.root)
}

func (s *Store) readDescriptor(artifactID string) (Descriptor, error) {
	path := s.descriptorPath(artifactID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Descriptor{}, ErrNotFound
	}
	if err != nil {
		return Descriptor{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > maxDescriptorBytes {
		return Descriptor{}, fmt.Errorf("%w: descriptor is not a protected regular file", ErrInvalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return Descriptor{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Descriptor{}, fmt.Errorf("%w: descriptor identity changed while opening", ErrInvalid)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxDescriptorBytes+1))
	decoder.DisallowUnknownFields()
	var descriptor Descriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return Descriptor{}, fmt.Errorf("%w: decode descriptor: %v", ErrInvalid, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Descriptor{}, fmt.Errorf("%w: descriptor has trailing content", ErrInvalid)
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, err
	}
	if descriptor.ArtifactID != artifactID || descriptor.SessionID != s.sessionID {
		return Descriptor{}, fmt.Errorf("%w: descriptor storage identity mismatch", ErrInvalid)
	}
	return descriptor, nil
}

func (d Descriptor) Validate() error {
	if d.SchemaVersion != SchemaVersion || !d.Complete {
		return fmt.Errorf("%w: descriptor is incomplete or unsupported", ErrInvalid)
	}
	if err := validateArtifactID(d.ArtifactID); err != nil {
		return err
	}
	if !validName(d.SessionID) || filepath.Base(d.SessionID) != d.SessionID {
		return fmt.Errorf("%w: descriptor session identity is invalid", ErrInvalid)
	}
	if err := validateKind(d.Kind); err != nil {
		return err
	}
	if d.MediaType != MediaTypeGitBundle || d.Size < 0 || d.CreatedAt.IsZero() {
		return fmt.Errorf("%w: descriptor metadata is invalid", ErrInvalid)
	}
	if !validSHA256(d.SHA256) {
		return fmt.Errorf("%w: descriptor digest is invalid", ErrInvalid)
	}
	return nil
}

func validateKind(kind Kind) error {
	switch kind {
	case KindGitInputBundle, KindGitResultBundle:
		return nil
	default:
		return fmt.Errorf("%w: unsupported artifact kind %q", ErrInvalid, kind)
	}
}

func validateArtifactID(value string) error {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value || parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 {
		return fmt.Errorf("%w: artifact ID is invalid", ErrInvalid)
	}
	return nil
}

func validName(value string) bool {
	if value != strings.TrimSpace(value) || value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n/\\") {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '.', char == '_', char == '-':
		default:
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func copyBounded(ctx context.Context, destination io.Writer, source io.Reader, limit int64) (int64, error) {
	buffer := make([]byte, 128*1024)
	if limit <= 0 || limit == int64(^uint64(0)>>1) {
		return 0, fmt.Errorf("%w: invalid copy limit", ErrInvalid)
	}
	limited := &io.LimitedReader{R: source, N: limit + 1}
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		count, readErr := limited.Read(buffer)
		if count > 0 {
			if written+int64(count) > limit {
				return written, ErrTooLarge
			}
			output, writeErr := destination.Write(buffer[:count])
			written += int64(output)
			if writeErr != nil {
				return written, writeErr
			}
			if output != count {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func (s *Store) descriptorPath(id string) string { return filepath.Join(s.root, id+".json") }
func (s *Store) dataPath(id string) string       { return filepath.Join(s.root, id+".bundle") }
func (s *Store) tombstonePath(id string) string {
	return filepath.Join(s.root, ".delete-"+id+".json")
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync runtime artifact directory: %w", err)
	}
	return nil
}
