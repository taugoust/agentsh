package externalrunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func stageWorkspace(ctx context.Context, source, destination string) (WorkspaceBaseline, error) {
	source, err := filepath.EvalSymlinks(source)
	if err != nil {
		return WorkspaceBaseline{}, fmt.Errorf("resolve staged workspace source: %w", err)
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return WorkspaceBaseline{}, fmt.Errorf("staged workspace destination must be clean and absolute")
	}
	if pathsOverlap(source, destination) {
		return WorkspaceBaseline{}, fmt.Errorf("staged workspace source and destination overlap")
	}
	if info, err := os.Lstat(source); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return WorkspaceBaseline{}, fmt.Errorf("staged workspace source is not a direct directory")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return WorkspaceBaseline{}, fmt.Errorf("staged workspace destination already exists or is ambiguous")
	}
	parent := filepath.Dir(destination)
	temporary, err := os.MkdirTemp(parent, ".workspace-stage-")
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return WorkspaceBaseline{}, err
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("staged workspace traversal escaped its source")
		}
		if relative == "." {
			return nil
		}
		// .direnv is host-local generated state, is excluded from Draft review
		// and Apply, and commonly contains absolute Nix-store symlinks that have
		// no stable meaning inside the guest. Never stage it into the MicroVM.
		if relative == ".direnv" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(temporary, relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return os.Mkdir(target, (info.Mode().Perm()|0o700)&0o777)
		case info.Mode().IsRegular():
			return copyStagedRegularFile(ctx, path, target, info)
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if filepath.IsAbs(link) {
				return fmt.Errorf("staged workspace refuses absolute symlink %s", relative)
			}
			resolved, err := filepath.EvalSymlinks(filepath.Join(filepath.Dir(path), link))
			if err != nil {
				return fmt.Errorf("staged workspace refuses dangling symlink %s: %w", relative, err)
			}
			resolved, err = filepath.Abs(resolved)
			if err != nil || (resolved != source && !strings.HasPrefix(resolved, source+string(filepath.Separator))) {
				return fmt.Errorf("staged workspace symlink %s escapes its source", relative)
			}
			return os.Symlink(link, target)
		default:
			return fmt.Errorf("staged workspace refuses special file %s", relative)
		}
	})
	if err != nil {
		return WorkspaceBaseline{}, err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return WorkspaceBaseline{}, fmt.Errorf("publish staged workspace: %w", err)
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return WorkspaceBaseline{}, err
	}
	staged, err := snapshotWorkspace(ctx, destination)
	if err != nil {
		return WorkspaceBaseline{}, fmt.Errorf("snapshot staged workspace: %w", err)
	}
	baseline, err := snapshotWorkspace(ctx, source)
	if err != nil {
		return WorkspaceBaseline{}, fmt.Errorf("snapshot workspace source baseline: %w", err)
	}
	if drift := compareStagedWorkspaceContent(staged, baseline); len(drift) != 0 {
		return WorkspaceBaseline{}, fmt.Errorf("workspace source changed during staging at %s", drift[0].Path)
	}
	return baseline, nil
}

func copyStagedRegularFile(ctx context.Context, source, destination string, scanned os.FileInfo) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(scanned, opened) {
		return fmt.Errorf("staged source file identity changed while opening")
	}
	mode := (opened.Mode().Perm() | 0o600) & 0o777
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	buffer := make([]byte, 128*1024)
	var copyErr error
	for {
		if err := ctx.Err(); err != nil {
			copyErr = err
			break
		}
		count, readErr := input.Read(buffer)
		if count > 0 {
			if _, err := output.Write(buffer[:count]); err != nil {
				copyErr = err
				break
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			copyErr = readErr
			break
		}
	}
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	separator := string(filepath.Separator)
	return left == right || strings.HasPrefix(left, right+separator) || strings.HasPrefix(right, left+separator)
}
