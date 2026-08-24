//go:build linux

package externalrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const cidLeaseLockName = "leases.lock"

func allocateCID(ctx context.Context, root, sessionID string, cidMin, cidMax uint32) (CIDLease, error) {
	lock, dir, err := acquireCIDLock(ctx, root, true)
	if err != nil {
		return CIDLease{}, err
	}
	defer lock.Close()
	defer dir.Close()

	for cid := cidMin; ; cid++ {
		if err := ctx.Err(); err != nil {
			return CIDLease{}, err
		}
		path := cidLeasePath(root, cid)
		fd, openErr := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if openErr == unix.EEXIST {
			if cid == cidMax {
				break
			}
			continue
		}
		if openErr != nil {
			return CIDLease{}, fmt.Errorf("reserve external runner CID %d: %w", cid, openErr)
		}
		file := os.NewFile(uintptr(fd), filepath.Base(path))
		identity, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			return CIDLease{}, fmt.Errorf("inspect reserved external runner CID lease: %w", statErr)
		}
		leaseID, randomErr := randomLeaseID()
		if randomErr != nil {
			_ = file.Close()
			_ = removeCIDLeaseIfSame(path, identity)
			return CIDLease{}, randomErr
		}
		lease := CIDLease{
			SchemaVersion: cidLeaseSchemaVersion,
			CID:           cid, SessionID: sessionID, LeaseID: leaseID, CreatedAt: time.Now().UTC(),
		}
		data, marshalErr := json.Marshal(lease)
		writeErr := marshalErr
		if writeErr == nil {
			_, writeErr = file.Write(append(data, '\n'))
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			_ = removeCIDLeaseIfSame(path, identity)
			return CIDLease{}, fmt.Errorf("persist external runner CID lease: %w", err)
		}
		if err := dir.Sync(); err != nil {
			removeErr := removeCIDLeaseIfSame(path, identity)
			return CIDLease{}, errors.Join(fmt.Errorf("sync external runner CID lease directory: %w", err), removeErr)
		}
		return lease, nil
	}
	return CIDLease{}, fmt.Errorf("external runner VSOCK CID range %d-%d is exhausted", cidMin, cidMax)
}

func verifyCID(ctx context.Context, root string, lease CIDLease, cidMin, cidMax uint32) error {
	lock, dir, err := acquireCIDLock(ctx, root, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer dir.Close()
	_, current, err := readCIDLease(root, lease.CID, cidMin, cidMax)
	if err != nil {
		return err
	}
	if !sameCIDLease(current, lease) {
		return fmt.Errorf("external runner CID lease identity mismatch")
	}
	return nil
}

func releaseCID(ctx context.Context, root string, lease CIDLease, cidMin, cidMax uint32) error {
	lock, dir, err := acquireCIDLock(ctx, root, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer dir.Close()
	identity, current, err := readCIDLease(root, lease.CID, cidMin, cidMax)
	if err != nil {
		return err
	}
	if !sameCIDLease(current, lease) {
		return fmt.Errorf("external runner CID lease identity mismatch")
	}
	path := cidLeasePath(root, lease.CID)
	latest, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("revalidate external runner CID lease: %w", err)
	}
	if !os.SameFile(identity, latest) {
		return fmt.Errorf("external runner CID lease file identity changed before release")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("release external runner CID lease: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync released external runner CID lease: %w", err)
	}
	return nil
}

func acquireCIDLock(ctx context.Context, root string, create bool) (io.Closer, *os.File, error) {
	if create {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create external runner CID lease root: %w", err)
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect external runner CID lease root: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	var ownerUID uint32
	if ok {
		ownerUID = stat.Uid
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 || !ok || !trustedCIDOwner(ownerUID) {
		return nil, nil, fmt.Errorf("external runner CID lease root has unsafe identity or permissions: mode=%s uid=%d euid=%d", info.Mode(), ownerUID, os.Geteuid())
	}
	dir, err := os.Open(root)
	if err != nil {
		return nil, nil, fmt.Errorf("open external runner CID lease root: %w", err)
	}
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("external runner CID lease root identity changed while opening")
	}
	lockPath := filepath.Join(root, cidLeaseLockName)
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("open external runner CID lease lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), cidLeaseLockName)
	lockInfo, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		_ = dir.Close()
		return nil, nil, fmt.Errorf("inspect external runner CID lease lock: %w", err)
	}
	lockStat, statOK := lockInfo.Sys().(*syscall.Stat_t)
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 || !statOK || !trustedCIDOwner(lockStat.Uid) {
		_ = lock.Close()
		_ = dir.Close()
		return nil, nil, fmt.Errorf("external runner CID lease lock has unsafe identity or permissions")
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = lock.Close()
			_ = dir.Close()
			return nil, nil, err
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return &flockFile{File: lock, fd: fd}, dir, nil
		} else if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			_ = lock.Close()
			_ = dir.Close()
			return nil, nil, fmt.Errorf("lock external runner CID leases: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type flockFile struct {
	*os.File
	fd int
}

func (f *flockFile) Close() error {
	return errors.Join(unix.Flock(f.fd, unix.LOCK_UN), f.File.Close())
}

func readCIDLease(root string, cid, cidMin, cidMax uint32) (os.FileInfo, CIDLease, error) {
	path := cidLeasePath(root, cid)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, CIDLease{}, fmt.Errorf("inspect external runner CID lease: %w", err)
	}
	leaseStat, statOK := before.Sys().(*syscall.Stat_t)
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() > 4096 || !statOK || !trustedCIDOwner(leaseStat.Uid) {
		return nil, CIDLease{}, fmt.Errorf("external runner CID lease file is unsafe")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, CIDLease{}, fmt.Errorf("open external runner CID lease: %w", err)
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, CIDLease{}, fmt.Errorf("external runner CID lease identity changed while opening")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	var lease CIDLease
	if err := decoder.Decode(&lease); err != nil || requireEOF(decoder) != nil {
		return nil, CIDLease{}, fmt.Errorf("decode external runner CID lease")
	}
	if err := lease.Validate(cidMin, cidMax); err != nil || lease.CID != cid {
		return nil, CIDLease{}, fmt.Errorf("external runner CID lease content is invalid")
	}
	return before, lease, nil
}

func cidLeasePath(root string, cid uint32) string {
	return filepath.Join(root, fmt.Sprintf("%d.json", cid))
}

func trustedCIDOwner(uid uint32) bool {
	// Root-owned state is trusted and is also how Nix's user-namespace sandbox
	// presents files created by the unprivileged build user.
	return uid == 0 || uid == uint32(os.Geteuid())
}

func removeCIDLeaseIfSame(path string, identity os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if identity == nil || !os.SameFile(identity, current) {
		return fmt.Errorf("external runner CID lease file identity changed before cleanup")
	}
	return os.Remove(path)
}

func sameCIDLease(left, right CIDLease) bool {
	return left.SchemaVersion == right.SchemaVersion && left.CID == right.CID && left.SessionID == right.SessionID &&
		left.LeaseID == right.LeaseID && left.CreatedAt.Equal(right.CreatedAt)
}

func randomLeaseID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate external runner CID lease identity: %w", err)
	}
	return hex.EncodeToString(value), nil
}
