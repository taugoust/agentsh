package externalrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	WorkspaceBaselineSchemaVersion = 1
	workspaceBaselineMaxBytes      = 64 << 20
)

type WorkspaceBaseline struct {
	SchemaVersion int                      `json:"schema_version"`
	Source        string                   `json:"source"`
	RootMode      uint32                   `json:"root_mode"`
	Entries       []WorkspaceBaselineEntry `json:"entries"`
}

type WorkspaceBaselineEntry struct {
	Path   string `json:"path_b64"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target_b64,omitempty"`
}

type WorkspaceDrift struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func CaptureWorkspaceBaseline(ctx context.Context, source string) (WorkspaceBaseline, error) {
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	return snapshotWorkspace(ctx, resolved)
}

func snapshotWorkspace(ctx context.Context, root string) (WorkspaceBaseline, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return WorkspaceBaseline{}, fmt.Errorf("workspace snapshot root must be clean and absolute")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return WorkspaceBaseline{}, fmt.Errorf("workspace snapshot root is not a direct directory")
	}
	baseline := WorkspaceBaseline{
		SchemaVersion: WorkspaceBaselineSchemaVersion,
		Source:        root,
		RootMode:      uint32(rootInfo.Mode().Perm()),
		Entries:       make([]WorkspaceBaselineEntry, 0),
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("workspace snapshot traversal escaped its root")
		}
		if relative == "." {
			return nil
		}
		if workspaceReviewExcluded(relative) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		record := WorkspaceBaselineEntry{Path: encodeWorkspacePath(relative)}
		switch {
		case info.IsDir():
			record.Type = "directory"
			record.Mode = uint32(info.Mode().Perm())
		case info.Mode().IsRegular():
			record.Type = "regular"
			record.Mode = uint32(info.Mode().Perm())
			record.Size = info.Size()
			record.SHA256, err = hashWorkspaceFile(ctx, path, info)
			if err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink != 0:
			record.Type = "symlink"
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return readErr
			}
			record.Target = encodeWorkspacePath(target)
		default:
			return fmt.Errorf("workspace snapshot refuses special file %s", relative)
		}
		baseline.Entries = append(baseline.Entries, record)
		return nil
	})
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	sort.Slice(baseline.Entries, func(left, right int) bool {
		return baseline.Entries[left].Path < baseline.Entries[right].Path
	})
	return baseline, baseline.Validate()
}

func workspaceReviewExcluded(relative string) bool {
	first := relative
	if index := strings.IndexRune(relative, filepath.Separator); index >= 0 {
		first = relative[:index]
	}
	return first == ".git" || first == ".direnv"
}

func hashWorkspaceFile(ctx context.Context, path string, scanned os.FileInfo) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(scanned, before) {
		return "", fmt.Errorf("workspace file identity changed while hashing")
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			if _, err := hash.Write(buffer[:count]); err != nil {
				return "", err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return "", fmt.Errorf("workspace file changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func compareStagedWorkspaceContent(staged, source WorkspaceBaseline) []WorkspaceDrift {
	staged.Entries = append([]WorkspaceBaselineEntry(nil), staged.Entries...)
	sourceByPath := make(map[string]WorkspaceBaselineEntry, len(source.Entries))
	for _, entry := range source.Entries {
		sourceByPath[entry.Path] = entry
	}
	for index := range staged.Entries {
		if sourceEntry, ok := sourceByPath[staged.Entries[index].Path]; ok && sourceEntry.Type == staged.Entries[index].Type {
			staged.Entries[index].Mode = sourceEntry.Mode
		}
	}
	return compareWorkspaceBaselines(staged, source)
}

func compareWorkspaceBaselines(expected, current WorkspaceBaseline) []WorkspaceDrift {
	drift := make([]WorkspaceDrift, 0)
	expectedEntries := make(map[string]WorkspaceBaselineEntry, len(expected.Entries))
	currentEntries := make(map[string]WorkspaceBaselineEntry, len(current.Entries))
	for _, entry := range expected.Entries {
		expectedEntries[entry.Path] = entry
	}
	for _, entry := range current.Entries {
		currentEntries[entry.Path] = entry
	}
	paths := make([]string, 0, len(expectedEntries)+len(currentEntries))
	seen := make(map[string]struct{}, len(expectedEntries)+len(currentEntries))
	for path := range expectedEntries {
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for path := range currentEntries {
		if _, ok := seen[path]; !ok {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	for _, encodedPath := range paths {
		expectedEntry, expectedOK := expectedEntries[encodedPath]
		currentEntry, currentOK := currentEntries[encodedPath]
		path := displayWorkspacePath(encodedPath)
		switch {
		case !expectedOK:
			drift = append(drift, WorkspaceDrift{Path: path, Reason: "added to real workspace"})
		case !currentOK:
			drift = append(drift, WorkspaceDrift{Path: path, Reason: "removed from real workspace"})
		case expectedEntry != currentEntry:
			drift = append(drift, WorkspaceDrift{Path: path, Reason: "content, type, mode, or symlink target changed"})
		}
	}
	return drift
}

func WriteWorkspaceBaseline(path string, baseline WorkspaceBaseline) error {
	if err := baseline.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > workspaceBaselineMaxBytes {
		return fmt.Errorf("workspace baseline exceeds size limit")
	}
	if err := writeExclusivePrivateFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write workspace baseline: %w", err)
	}
	return nil
}

func ReadWorkspaceBaseline(path string) (WorkspaceBaseline, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() > workspaceBaselineMaxBytes {
		return WorkspaceBaseline{}, fmt.Errorf("workspace baseline file is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return WorkspaceBaseline{}, fmt.Errorf("workspace baseline identity changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, workspaceBaselineMaxBytes+1))
	if err != nil {
		return WorkspaceBaseline{}, fmt.Errorf("read workspace baseline: %w", err)
	}
	if len(data) > workspaceBaselineMaxBytes {
		return WorkspaceBaseline{}, fmt.Errorf("workspace baseline exceeds size limit")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return WorkspaceBaseline{}, fmt.Errorf("workspace baseline changed while reading")
	}
	var baseline WorkspaceBaseline
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return WorkspaceBaseline{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return WorkspaceBaseline{}, fmt.Errorf("workspace baseline has trailing JSON")
	}
	return baseline, baseline.Validate()
}

func VerifyWorkspaceBaseline(ctx context.Context, baseline WorkspaceBaseline) ([]WorkspaceDrift, error) {
	if err := baseline.Validate(); err != nil {
		return nil, err
	}
	current, err := snapshotWorkspace(ctx, baseline.Source)
	if err != nil {
		return nil, err
	}
	current.Source = baseline.Source
	return compareWorkspaceBaselines(baseline, current), nil
}

func (b WorkspaceBaseline) Validate() error {
	if b.SchemaVersion != WorkspaceBaselineSchemaVersion || !filepath.IsAbs(b.Source) || filepath.Clean(b.Source) != b.Source {
		return fmt.Errorf("workspace baseline identity is invalid")
	}
	if b.RootMode > 0o777 {
		return fmt.Errorf("workspace baseline root mode is invalid")
	}
	previous := ""
	for _, entry := range b.Entries {
		decoded, err := base64.RawStdEncoding.DecodeString(entry.Path)
		if err != nil || len(decoded) == 0 {
			return fmt.Errorf("workspace baseline path is invalid")
		}
		relative := string(decoded)
		if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || workspaceReviewExcluded(relative) {
			return fmt.Errorf("workspace baseline path is unsafe")
		}
		if previous != "" && entry.Path <= previous {
			return fmt.Errorf("workspace baseline paths are not unique and ordered")
		}
		previous = entry.Path
		switch entry.Type {
		case "directory":
			if entry.Mode > 0o777 || entry.Size != 0 || entry.SHA256 != "" || entry.Target != "" {
				return fmt.Errorf("workspace baseline directory is invalid")
			}
		case "regular":
			if entry.Mode > 0o777 || entry.Size < 0 || len(entry.SHA256) != sha256.Size*2 || entry.Target != "" {
				return fmt.Errorf("workspace baseline regular file is invalid")
			}
			if _, err := hex.DecodeString(entry.SHA256); err != nil {
				return fmt.Errorf("workspace baseline regular digest is invalid")
			}
		case "symlink":
			if entry.Mode != 0 || entry.Size != 0 || entry.SHA256 != "" {
				return fmt.Errorf("workspace baseline symlink is invalid")
			}
			target, err := base64.RawStdEncoding.DecodeString(entry.Target)
			if err != nil || len(target) == 0 {
				return fmt.Errorf("workspace baseline symlink target is invalid")
			}
		default:
			return fmt.Errorf("workspace baseline entry type is invalid")
		}
	}
	return nil
}

func encodeWorkspacePath(path string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(path))
}

func displayWorkspacePath(encoded string) string {
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "<invalid>"
	}
	return fmt.Sprintf("%q", string(decoded))
}
