//go:build linux && cgo

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/agentsh/agentsh/internal/composition"
	"github.com/agentsh/agentsh/internal/landlock"
	"golang.org/x/sys/unix"
)

const (
	sysOpenTree  = 428
	sysMoveMount = 429
	sysFSOpen    = 430
	sysFSConfig  = 431
	sysFSMount   = 432

	fsOpenCloexec     = 0x00000001
	fsMountCloexec    = 0x00000001
	fsconfigSetString = 1
	fsconfigCmdCreate = 6
	moveMountEmpty    = 0x00000004
	openTreeClone     = 0x00000001
	openTreeCloexec   = unix.O_CLOEXEC

	mountAttrNoSUID = 0x00000002
	mountAttrNoDev  = 0x00000004
	mountAttrNoExec = 0x00000008
)

type compositionSetupState struct {
	kinds     []composition.SetupObjectKind
	paths     []string
	rights    []uint64
	files     []*os.File
	owned     []*os.File
	poolRoot  string
	poolSlots []string
}

func (s *compositionSetupState) cleanupPoolPaths() error {
	if s == nil {
		return nil
	}
	var errs []error
	remaining := make([]string, 0, len(s.poolSlots))
	for index := len(s.poolSlots) - 1; index >= 0; index-- {
		slot := s.poolSlots[index]
		if err := unix.Unmount(slot, unix.MNT_DETACH); err != nil && err != unix.EINVAL && err != unix.ENOENT {
			errs = append(errs, fmt.Errorf("detach composition pool slot %q: %w", slot, err))
		}
		if err := os.Remove(slot); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove composition pool slot %q: %w", slot, err))
			remaining = append(remaining, slot)
		}
	}
	s.poolSlots = remaining
	if s.poolRoot != "" && len(s.poolSlots) == 0 {
		if err := os.Remove(s.poolRoot); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove composition pool root %q: %w", s.poolRoot, err))
		} else {
			s.poolRoot = ""
		}
	}
	return errors.Join(errs...)
}

func (s *compositionSetupState) closeOwned() {
	if s == nil {
		return
	}
	for _, file := range s.owned {
		if file != nil {
			_ = file.Close()
		}
	}
	s.owned = nil
}

func compositionSetupFD() (int, error) {
	value := os.Getenv(composition.SetupFDEnv)
	if value == "" {
		return -1, fmt.Errorf("%s is missing", composition.SetupFDEnv)
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 {
		return -1, fmt.Errorf("invalid %s %q", composition.SetupFDEnv, value)
	}
	return fd, nil
}

func syntheticWriteRights(abi int) uint64 {
	rights := uint64(
		landlock.LANDLOCK_ACCESS_FS_READ_FILE |
			landlock.LANDLOCK_ACCESS_FS_READ_DIR |
			landlock.LANDLOCK_ACCESS_FS_WRITE_FILE |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			landlock.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			landlock.LANDLOCK_ACCESS_FS_MAKE_DIR |
			landlock.LANDLOCK_ACCESS_FS_MAKE_REG |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			landlock.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			landlock.LANDLOCK_ACCESS_FS_MAKE_SYM,
	)
	if abi >= 2 {
		rights |= landlock.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		rights |= landlock.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return rights
}

func syntheticRootRights(_ int) uint64 {
	// The detached root is a read/execute destination anchor only. Giving its
	// ancestor rule mutation rights would confer MAKE/REMOVE/REFER authority on
	// every bind mounted below it, which mount attributes cannot selectively
	// subtract. Writable fresh trees use separately tagged synthetic slots;
	// writable pre-existing binds must retain their own exact base-policy tag.
	return landlock.LANDLOCK_ACCESS_FS_READ_FILE |
		landlock.LANDLOCK_ACCESS_FS_READ_DIR |
		landlock.LANDLOCK_ACCESS_FS_EXECUTE
}

func rawCString(value string) (*byte, error) {
	return unix.BytePtrFromString(value)
}

func fsconfigString(fd int, key, value string) error {
	keyPointer, err := rawCString(key)
	if err != nil {
		return err
	}
	valuePointer, err := rawCString(value)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall6(
		sysFSConfig,
		uintptr(fd),
		fsconfigSetString,
		uintptr(unsafe.Pointer(keyPointer)),
		uintptr(unsafe.Pointer(valuePointer)),
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func mountSyntheticTmpfs(target string, maxBytes int64) error {
	filesystem, err := rawCString("tmpfs")
	if err != nil {
		return err
	}
	fsFDValue, _, errno := unix.Syscall(sysFSOpen, uintptr(unsafe.Pointer(filesystem)), fsOpenCloexec, 0)
	if errno != 0 {
		return fmt.Errorf("fsopen tmpfs: %w", errno)
	}
	fsFD := int(fsFDValue)
	defer unix.Close(fsFD)
	if err := fsconfigString(fsFD, "size", strconv.FormatInt(maxBytes, 10)); err != nil {
		return fmt.Errorf("configure tmpfs size: %w", err)
	}
	if err := fsconfigString(fsFD, "mode", "0755"); err != nil {
		return fmt.Errorf("configure tmpfs mode: %w", err)
	}
	_, _, errno = unix.Syscall6(sysFSConfig, uintptr(fsFD), fsconfigCmdCreate, 0, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("create tmpfs context: %w", errno)
	}
	mountFDValue, _, errno := unix.Syscall(
		sysFSMount,
		uintptr(fsFD),
		fsMountCloexec,
		mountAttrNoSUID|mountAttrNoDev|mountAttrNoExec,
	)
	if errno != 0 {
		return fmt.Errorf("fsmount tmpfs: %w", errno)
	}
	mountFD := int(mountFDValue)
	defer unix.Close(mountFD)
	empty, _ := rawCString("")
	targetPointer, err := rawCString(target)
	if err != nil {
		return err
	}
	targetDirectoryFD := int(unix.AT_FDCWD)
	_, _, errno = unix.Syscall6(
		sysMoveMount,
		uintptr(mountFD),
		uintptr(unsafe.Pointer(empty)),
		uintptr(targetDirectoryFD),
		uintptr(unsafe.Pointer(targetPointer)),
		moveMountEmpty,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("attach synthetic tmpfs: %w", errno)
	}
	return nil
}

func cloneSyntheticMount(path string) (*os.File, error) {
	pathPointer, err := rawCString(path)
	if err != nil {
		return nil, err
	}
	currentWorkingDirectory := int(unix.AT_FDCWD)
	value, _, errno := unix.Syscall6(
		sysOpenTree,
		uintptr(currentWorkingDirectory),
		uintptr(unsafe.Pointer(pathPointer)),
		openTreeClone|openTreeCloexec|unix.AT_RECURSIVE,
		0,
		0,
		0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("clone synthetic tmpfs mount: %w", errno)
	}
	return os.NewFile(value, "agentsh-composition-synthetic-mount"), nil
}

// prepareCompositionSetup provisions actual tmpfs roots before Landlock is
// enforced. A later fresh mount cannot inherit rights from an underlying tagged
// directory, so each bounded pool slot is itself a pre-enforcement mount and
// rule object.
func prepareCompositionSetup(cfg *WrapperConfig, prepared *preparedLandlockRuleset) (_ *compositionSetupState, resultErr error) {
	if cfg == nil || cfg.SandboxComposition == "" {
		return nil, nil
	}
	if cfg.SandboxComposition != composition.Mode || prepared == nil || prepared.fd < 0 {
		return nil, fmt.Errorf("composition requires a prepared Landlock ruleset")
	}
	if cfg.CommandJail == nil || !cfg.CommandJail.Required {
		return nil, fmt.Errorf("composition requires the strict command jail")
	}
	if !filepath.IsAbs(cfg.CompositionScratchRoot) || cfg.CompositionSyntheticMounts <= 0 || cfg.CompositionMaxTransitions <= 0 || cfg.CompositionMaxDataBytes <= 0 {
		return nil, fmt.Errorf("composition synthetic pool configuration is invalid")
	}
	poolRoot, err := os.MkdirTemp(cfg.CompositionScratchRoot, ".agentsh-composition-pool-")
	if err != nil {
		return nil, fmt.Errorf("create composition pool: %w", err)
	}
	if err := os.Chmod(poolRoot, 0o700); err != nil {
		_ = os.Remove(poolRoot)
		return nil, fmt.Errorf("protect composition pool: %w", err)
	}

	capacity := len(prepared.objects) + len(cfg.DenyPaths) + cfg.CompositionSyntheticMounts + cfg.CompositionMaxTransitions
	state := &compositionSetupState{
		kinds:    make([]composition.SetupObjectKind, 0, capacity),
		paths:    make([]string, 0, capacity),
		rights:   make([]uint64, 0, capacity),
		files:    make([]*os.File, 0, capacity),
		owned:    make([]*os.File, 0, len(cfg.DenyPaths)+cfg.CompositionSyntheticMounts+cfg.CompositionMaxTransitions),
		poolRoot: poolRoot,
	}
	defer func() {
		if resultErr != nil {
			state.closeOwned()
			resultErr = errors.Join(resultErr, state.cleanupPoolPaths())
		}
	}()
	for index := range prepared.objects {
		object := &prepared.objects[index]
		if object.File == nil {
			return nil, fmt.Errorf("prepared Landlock object %d is closed", index)
		}
		duplicateFD, err := unix.FcntlInt(object.File.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			return nil, fmt.Errorf("duplicate prepared Landlock object %d: %w", index, err)
		}
		duplicate := os.NewFile(uintptr(duplicateFD), "agentsh-composition-policy-object")
		if duplicate == nil {
			_ = unix.Close(duplicateFD)
			return nil, fmt.Errorf("retain duplicate Landlock object %d", index)
		}
		state.kinds = append(state.kinds, composition.SetupObjectPolicy)
		state.paths = append(state.paths, object.Path)
		state.rights = append(state.rights, object.Rights)
		state.files = append(state.files, duplicate)
		state.owned = append(state.owned, duplicate)
	}

	// Retain existing denied objects even though they are deliberately absent
	// from the Landlock allow rules. Device/inode ancestry lets the broker keep
	// these exclusions authoritative through bind aliases.
	for _, deniedPath := range cfg.DenyPaths {
		if index := strings.IndexAny(deniedPath, "*?["); index >= 0 {
			deniedPath = strings.TrimSuffix(deniedPath[:index], string(filepath.Separator))
		}
		if !filepath.IsAbs(deniedPath) {
			continue
		}
		deniedPath = filepath.Clean(deniedPath)
		fd, openErr := unix.Open(deniedPath, unix.O_PATH|unix.O_CLOEXEC, 0)
		if openErr != nil {
			if openErr == unix.ENOENT {
				continue
			}
			return nil, fmt.Errorf("retain denied composition object %q: %w", deniedPath, openErr)
		}
		file := os.NewFile(uintptr(fd), "agentsh-composition-denied-object")
		state.kinds = append(state.kinds, composition.SetupObjectPolicyDeny)
		state.paths = append(state.paths, deniedPath)
		state.rights = append(state.rights, 0)
		state.files = append(state.files, file)
		state.owned = append(state.owned, file)
	}

	// A bounded executable synthetic-root pool is followed by the bounded
	// noexec scratch pool. Each root is a destination-rights anchor: source
	// rights are checked before a bind can be placed beneath it, and mount
	// attributes enforce the admitted subset.
	totalSynthetic := cfg.CompositionMaxTransitions + cfg.CompositionSyntheticMounts
	for index := 0; index < totalSynthetic; index++ {
		slot := filepath.Join(poolRoot, fmt.Sprintf("slot-%04d", index))
		if err := os.Mkdir(slot, 0o700); err != nil {
			return nil, fmt.Errorf("create composition pool slot %d: %w", index, err)
		}
		state.poolSlots = append(state.poolSlots, slot)
		if err := mountSyntheticTmpfs(slot, cfg.CompositionMaxDataBytes); err != nil {
			return nil, fmt.Errorf("mount composition pool slot %d: %w", index, err)
		}
		rights := syntheticWriteRights(prepared.abi)
		kind := composition.SetupObjectSyntheticRW
		if index < cfg.CompositionMaxTransitions {
			rights = syntheticRootRights(prepared.abi)
			kind = composition.SetupObjectSyntheticRoot
		}
		object, err := landlock.AddPathRuleObject(prepared.fd, slot, rights)
		if err != nil {
			return nil, fmt.Errorf("tag composition pool slot %d: %w", index, err)
		}
		prepared.objects = append(prepared.objects, object)
		mountObject, err := cloneSyntheticMount(slot)
		if err != nil {
			return nil, fmt.Errorf("clone composition pool slot %d: %w", index, err)
		}
		state.kinds = append(state.kinds, kind)
		state.paths = append(state.paths, slot)
		state.rights = append(state.rights, object.Rights)
		state.files = append(state.files, mountObject)
		state.owned = append(state.owned, mountObject)
	}
	if len(state.files) > 240 {
		return nil, fmt.Errorf("composition setup requires %d descriptors, maximum 240", len(state.files))
	}

	// The cloned mount FDs and retained Landlock objects remain authoritative
	// after their construction names disappear. Remove those names now: once
	// Landlock is enforced, mount topology changes and parent-directory removal
	// are deliberately unavailable to this process.
	if err := state.cleanupPoolPaths(); err != nil {
		return nil, fmt.Errorf("remove composition pool construction paths: %w", err)
	}
	return state, nil
}

func publishCompositionSetup(state *compositionSetupState) error {
	if state == nil {
		return nil
	}
	defer state.closeOwned()
	if state.poolRoot != "" || len(state.poolSlots) != 0 {
		return fmt.Errorf("composition pool construction paths survived pre-enforcement cleanup")
	}
	fd, err := compositionSetupFD()
	if err != nil {
		return err
	}
	connection := os.NewFile(uintptr(fd), "agentsh-composition-setup")
	if connection == nil {
		return fmt.Errorf("open composition setup channel")
	}
	defer connection.Close()
	defer os.Unsetenv(composition.SetupFDEnv)
	return composition.SendSetup(connection, composition.Mode, state.kinds, state.paths, state.rights, state.files)
}
