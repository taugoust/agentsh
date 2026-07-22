//go:build linux

package composition

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	SetupProtocolVersion = 1
	SetupFDEnv           = "AGENTSH_COMPOSITION_SETUP_FD"
	maxSetupBytes        = 1024 * 1024
	// Linux limits one SCM_RIGHTS message to SCM_MAX_FD (253). Keep margin for
	// implementation-specific ancillary data and fail before sendmsg.
	maxSetupObjects = 240
)

type SetupObjectKind string

const (
	SetupObjectPolicy        SetupObjectKind = "policy"
	SetupObjectPolicyDeny    SetupObjectKind = "policy-deny"
	SetupObjectSyntheticRoot SetupObjectKind = "synthetic-root"
	SetupObjectSyntheticRW   SetupObjectKind = "synthetic-rw-noexec"
)

type SetupObject struct {
	Kind   SetupObjectKind `json:"kind"`
	Path   string          `json:"path,omitempty"`
	Rights uint64          `json:"rights"`
	Device uint64          `json:"device"`
	Inode  uint64          `json:"inode"`
	Mode   uint32          `json:"mode"`
}

type SetupMessage struct {
	Version int           `json:"version"`
	Mode    string        `json:"mode"`
	Objects []SetupObject `json:"objects"`
}

type ReceivedSetupObject struct {
	SetupObject
	File *os.File
}

type ReceivedSetup struct {
	Version   int
	Mode      string
	Objects   []ReceivedSetupObject
	SenderPID int
	SenderUID uint32
	SenderGID uint32
}

func objectMetadata(kind SetupObjectKind, path string, rights uint64, file *os.File) (SetupObject, error) {
	if file == nil {
		return SetupObject{}, errors.New("nil setup object descriptor")
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &status); err != nil {
		return SetupObject{}, fmt.Errorf("stat setup object: %w", err)
	}
	return SetupObject{
		Kind:   kind,
		Path:   path,
		Rights: rights,
		Device: uint64(status.Dev),
		Inode:  status.Ino,
		Mode:   status.Mode,
	}, nil
}

// SendSetup transfers exact Landlock/synthetic objects over a trusted
// SOCK_SEQPACKET setup channel. Descriptor order is identical to message order.
func SendSetup(connection *os.File, mode string, kinds []SetupObjectKind, paths []string, rights []uint64, files []*os.File) error {
	if connection == nil {
		return errors.New("composition setup channel is missing")
	}
	if len(files) == 0 || len(files) > maxSetupObjects || len(kinds) != len(files) || len(paths) != len(files) || len(rights) != len(files) {
		return fmt.Errorf("invalid composition setup object vectors: files=%d kinds=%d paths=%d rights=%d", len(files), len(kinds), len(paths), len(rights))
	}
	message := SetupMessage{Version: SetupProtocolVersion, Mode: mode, Objects: make([]SetupObject, len(files))}
	fds := make([]int, len(files))
	for index, file := range files {
		metadata, err := objectMetadata(kinds[index], paths[index], rights[index], file)
		if err != nil {
			return fmt.Errorf("setup object %d: %w", index, err)
		}
		message.Objects[index] = metadata
		fds[index] = int(file.Fd())
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode composition setup: %w", err)
	}
	if len(encoded) > maxSetupBytes {
		return fmt.Errorf("composition setup exceeds %d bytes", maxSetupBytes)
	}
	oob := append(
		unix.UnixRights(fds...),
		unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())})...,
	)
	written, err := unix.SendmsgN(int(connection.Fd()), encoded, oob, nil, unix.MSG_NOSIGNAL)
	if err != nil {
		return fmt.Errorf("send composition setup: %w", err)
	}
	if written != len(encoded) {
		return fmt.Errorf("send composition setup: wrote %d of %d bytes", written, len(encoded))
	}
	if err := unix.Shutdown(int(connection.Fd()), unix.SHUT_WR); err != nil {
		return fmt.Errorf("seal composition setup channel: %w", err)
	}
	return nil
}

func receiveSetupPacket(connection *os.File) ([]byte, []int, *unix.Ucred, error) {
	if connection == nil {
		return nil, nil, nil, errors.New("composition setup channel is missing")
	}
	fd := int(connection.Fd())
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		return nil, nil, nil, fmt.Errorf("enable composition setup credentials: %w", err)
	}
	payload := make([]byte, maxSetupBytes+1)
	oob := make([]byte, unix.CmsgSpace(maxSetupObjects*4)+unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(fd, payload, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("receive composition setup: %w", err)
	}
	if n == 0 {
		return nil, nil, nil, errors.New("composition setup channel closed before publication")
	}
	controlMessages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	if parseErr != nil {
		return nil, nil, nil, fmt.Errorf("parse composition setup descriptors: %w", parseErr)
	}
	var fds []int
	var sender *unix.Ucred
	closeFDs := func() {
		for _, receivedFD := range fds {
			if receivedFD >= 0 {
				_ = unix.Close(receivedFD)
			}
		}
	}
	for _, control := range controlMessages {
		if control.Header.Level != unix.SOL_SOCKET {
			closeFDs()
			return nil, nil, nil, fmt.Errorf("composition setup carried ancillary level %d", control.Header.Level)
		}
		switch control.Header.Type {
		case unix.SCM_RIGHTS:
			rightsFDs, rightsErr := unix.ParseUnixRights(&control)
			if rightsErr != nil {
				closeFDs()
				return nil, nil, nil, fmt.Errorf("parse composition setup rights: %w", rightsErr)
			}
			fds = append(fds, rightsFDs...)
		case unix.SCM_CREDENTIALS:
			if sender != nil {
				closeFDs()
				return nil, nil, nil, errors.New("composition setup carried duplicate credentials")
			}
			credentials, credentialsErr := unix.ParseUnixCredentials(&control)
			if credentialsErr != nil {
				closeFDs()
				return nil, nil, nil, fmt.Errorf("parse composition setup credentials: %w", credentialsErr)
			}
			sender = credentials
		default:
			closeFDs()
			return nil, nil, nil, fmt.Errorf("composition setup carried unknown ancillary type %d", control.Header.Type)
		}
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n > maxSetupBytes {
		closeFDs()
		return nil, nil, nil, errors.New("composition setup message was truncated")
	}
	if sender == nil || sender.Pid <= 0 {
		closeFDs()
		return nil, nil, nil, errors.New("composition setup omitted SCM_CREDENTIALS")
	}
	return payload[:n], fds, sender, nil
}

func requireSetupChannelEOF(connection *os.File) error {
	payload := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(maxSetupObjects*4)+unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(int(connection.Fd()), payload, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return fmt.Errorf("confirm sealed composition setup channel: %w", err)
	}
	if oobn > 0 {
		messages, _ := unix.ParseSocketControlMessage(oob[:oobn])
		for _, message := range messages {
			fds, parseErr := unix.ParseUnixRights(&message)
			if parseErr == nil {
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
			}
		}
	}
	if n != 0 || oobn != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return errors.New("composition setup channel carried a duplicate message")
	}
	return nil
}

// ReceiveSetup receives and verifies one complete setup message. The kernel
// authenticates the sender of the descriptor-bearing packet with
// SCM_CREDENTIALS; the broker additionally binds that PID to the trusted
// wrapper executable selected for this command.
func ReceiveSetup(connection *os.File) (*ReceivedSetup, error) {
	payload, fds, sender, err := receiveSetupPacket(connection)
	if err != nil {
		return nil, err
	}
	closeFDs := func() {
		for _, fd := range fds {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	}
	defer closeFDs()
	if err := requireSetupChannelEOF(connection); err != nil {
		return nil, err
	}
	if err := validateUniqueJSONObject(payload); err != nil {
		return nil, fmt.Errorf("decode composition setup: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var message SetupMessage
	if err := decoder.Decode(&message); err != nil {
		return nil, fmt.Errorf("decode composition setup: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode composition setup: trailing JSON value")
	}
	if message.Version != SetupProtocolVersion || message.Mode != Mode || len(message.Objects) == 0 || len(message.Objects) > maxSetupObjects {
		return nil, fmt.Errorf("invalid composition setup header: version=%d mode=%q objects=%d", message.Version, message.Mode, len(message.Objects))
	}
	rootCount := 0
	for index, object := range message.Objects {
		if !filepath.IsAbs(object.Path) || filepath.Clean(object.Path) != object.Path {
			return nil, fmt.Errorf("composition setup object %d has invalid path %q", index, object.Path)
		}
		switch object.Kind {
		case SetupObjectPolicy:
			if object.Rights == 0 {
				return nil, fmt.Errorf("composition policy object %d has no rights", index)
			}
		case SetupObjectPolicyDeny:
			if object.Rights != 0 {
				return nil, fmt.Errorf("composition denied object %d carries rights", index)
			}
		case SetupObjectSyntheticRoot:
			rootCount++
			if object.Rights == 0 {
				return nil, fmt.Errorf("composition synthetic root %d has no rights", index)
			}
		case SetupObjectSyntheticRW:
			if object.Rights == 0 {
				return nil, fmt.Errorf("composition synthetic object %d has no rights", index)
			}
		default:
			return nil, fmt.Errorf("composition setup object %d has unknown kind %q", index, object.Kind)
		}
	}
	if rootCount == 0 {
		return nil, errors.New("composition setup omits synthetic roots")
	}
	if len(fds) != len(message.Objects) {
		return nil, fmt.Errorf("composition setup descriptor count %d does not match object count %d", len(fds), len(message.Objects))
	}

	setup := &ReceivedSetup{
		Version:   message.Version,
		Mode:      message.Mode,
		Objects:   make([]ReceivedSetupObject, len(fds)),
		SenderPID: int(sender.Pid),
		SenderUID: sender.Uid,
		SenderGID: sender.Gid,
	}
	for index, fd := range fds {
		file := os.NewFile(uintptr(fd), "agentsh-composition-policy-object")
		if file == nil {
			setup.Close()
			return nil, fmt.Errorf("retain composition setup descriptor %d", index)
		}
		// os.File owns this descriptor from here onward.
		fds[index] = -1
		actual, statErr := objectMetadata(message.Objects[index].Kind, message.Objects[index].Path, message.Objects[index].Rights, file)
		if statErr != nil || actual.Device != message.Objects[index].Device || actual.Inode != message.Objects[index].Inode || actual.Mode != message.Objects[index].Mode {
			_ = file.Close()
			setup.Close()
			if statErr != nil {
				return nil, fmt.Errorf("verify composition setup object %d: %w", index, statErr)
			}
			return nil, fmt.Errorf("composition setup object %d identity changed", index)
		}
		setup.Objects[index] = ReceivedSetupObject{SetupObject: message.Objects[index], File: file}
	}
	return setup, nil
}

func sameObject(left, right *os.File) (bool, error) {
	if left == nil || right == nil {
		return false, errors.New("nil policy object")
	}
	var leftStat, rightStat unix.Stat_t
	if err := unix.Fstat(int(left.Fd()), &leftStat); err != nil {
		return false, err
	}
	if err := unix.Fstat(int(right.Fd()), &rightStat); err != nil {
		return false, err
	}
	return leftStat.Dev == rightStat.Dev && leftStat.Ino == rightStat.Ino, nil
}

func retainedObjectContains(object *ReceivedSetupObject, source *os.File, sourcePath string) (bool, error) {
	if object == nil || object.File == nil || source == nil || !filepath.IsAbs(sourcePath) {
		return false, nil
	}
	var objectStat unix.Stat_t
	if err := unix.Fstat(int(object.File.Fd()), &objectStat); err != nil {
		return false, err
	}
	if objectStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return sameObject(object.File, source)
	}
	objectPath, err := os.Readlink(filepath.Join(string(filepath.Separator), "proc", "self", "fd", fmt.Sprint(object.File.Fd())))
	if err != nil || !filepath.IsAbs(objectPath) || strings.HasSuffix(objectPath, " (deleted)") {
		return false, fmt.Errorf("resolve retained policy object path")
	}
	objectPath = filepath.Clean(objectPath)
	relative, err := filepath.Rel(objectPath, filepath.Clean(sourcePath))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false, nil
	}
	if relative == "." {
		return sameObject(object.File, source)
	}
	fd, err := unix.Openat2(int(object.File.Fd()), relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return false, nil
	}
	resolved := os.NewFile(uintptr(fd), "composition-policy-descendant")
	if resolved == nil {
		_ = unix.Close(fd)
		return false, errors.New("retain resolved policy descendant")
	}
	defer resolved.Close()
	return sameObject(resolved, source)
}

// PolicyRights returns the union of retained AgentSH base-policy rights that
// provably apply to source. Textual ancestry is accepted only after resolving
// the same relative path beneath the retained rule descriptor and comparing
// object identity.
func (s *ReceivedSetup) PolicyRights(source *os.File, sourcePath string) (uint64, bool, error) {
	if s == nil || source == nil {
		return 0, false, typedError("E_COMPOSITION_SETUP_MISSING", "retained policy objects are unavailable")
	}
	var rights uint64
	matched := false
	for index := range s.Objects {
		object := &s.Objects[index]
		if (object.Kind != SetupObjectPolicy && object.Kind != SetupObjectSyntheticRoot && object.Kind != SetupObjectSyntheticRW) || object.File == nil {
			continue
		}
		contains, err := retainedObjectContains(object, source, sourcePath)
		if err != nil {
			return 0, false, typedError("E_COMPOSITION_SETUP_INVALID", "validate retained policy object: %v", err)
		}
		if contains {
			rights |= object.Rights
			matched = true
		}
	}
	return rights, matched, nil
}

// DeniedPolicyObject reports whether source is the retained denied object or a
// provable descendant. This preserves hard exclusions across bind aliases whose
// pathname no longer starts with the configured deny spelling.
func (s *ReceivedSetup) DeniedPolicyObject(source *os.File, sourcePath string) (bool, error) {
	if s == nil || source == nil {
		return false, typedError("E_COMPOSITION_SETUP_MISSING", "retained policy objects are unavailable")
	}
	for index := range s.Objects {
		object := &s.Objects[index]
		if object.Kind != SetupObjectPolicyDeny || object.File == nil {
			continue
		}
		contains, err := retainedObjectContains(object, source, sourcePath)
		if err != nil {
			return false, typedError("E_COMPOSITION_SETUP_INVALID", "validate retained denied object: %v", err)
		}
		if contains {
			return true, nil
		}
	}
	return false, nil
}

// ExactPolicyObject returns the retained base-policy object matching source.
// Ancestor pathname allowance is intentionally insufficient: moving a strict
// descendant away from its tagged mount ancestry loses the ancestor grant.
func (s *ReceivedSetup) ExactPolicyObject(source *os.File) (*ReceivedSetupObject, error) {
	if s == nil || source == nil {
		return nil, typedError("E_COMPOSITION_SETUP_MISSING", "retained policy objects are unavailable")
	}
	var sourceStat unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &sourceStat); err != nil {
		return nil, typedError("E_COMPOSITION_SETUP_INVALID", "stat resolved source object")
	}
	for index := range s.Objects {
		object := &s.Objects[index]
		if object.Kind != SetupObjectPolicy || object.File == nil {
			continue
		}
		var objectStat unix.Stat_t
		if err := unix.Fstat(int(object.File.Fd()), &objectStat); err != nil {
			return nil, typedError("E_COMPOSITION_SETUP_INVALID", "stat retained policy object")
		}
		if sourceStat.Dev == objectStat.Dev && sourceStat.Ino == objectStat.Ino {
			return object, nil
		}
	}
	return nil, typedError("E_COMPOSITION_TOPOLOGY_UNRESOLVED", "source is not an exact retained policy object")
}

func (s *ReceivedSetup) Close() {
	if s == nil {
		return
	}
	for index := range s.Objects {
		if s.Objects[index].File != nil {
			_ = s.Objects[index].File.Close()
			s.Objects[index].File = nil
		}
	}
}
