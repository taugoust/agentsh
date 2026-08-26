//go:build linux

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/agentsh/agentsh/internal/guestcontrol"
	"golang.org/x/sys/unix"
)

const (
	guestVolumeIdentitySchemaVersion = 1
	guestVolumeIdentityName          = "volume-identity.json"
	guestVolumeWorkspaceDirectory    = "workspace"
	guestMountInfoMaxBytes           = 4 * 1024 * 1024
)

type guestVolumeIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	SessionID     string `json:"session_id"`
	VolumeID      string `json:"volume_id"`
}

type guestMountInfoEntry struct {
	major      uint32
	minor      uint32
	root       string
	mountPoint string
	fsType     string
}

// verifyGuestControlWorkspaceVolume runs before any guest AgentSH process is
// started. Protocol v2 deliberately retains its pre-volume behavior.
func verifyGuestControlWorkspaceVolume(manifest guestcontrol.Manifest, workspace, volumeRoot string) error {
	if manifest.ProtocolVersion == guestcontrol.ProtocolVersionV2 {
		return nil
	}
	if manifest.ProtocolVersion != guestcontrol.ProtocolVersionV3 {
		return fmt.Errorf("guest control protocol version %d is unsupported", manifest.ProtocolVersion)
	}
	volumeRoot = strings.TrimSpace(volumeRoot)
	if volumeRoot == "" {
		return fmt.Errorf("guest control protocol version 3 requires --volume-root")
	}
	if filepath.Clean(volumeRoot) != volumeRoot {
		return fmt.Errorf("guest control volume root must be a dedicated clean absolute path")
	}
	workspace = filepath.Clean(workspace)
	rootPath := string(filepath.Separator)
	expectedWorkspace := filepath.Join(rootPath, guestVolumeWorkspaceDirectory)
	if !filepath.IsAbs(volumeRoot) || volumeRoot == rootPath {
		return fmt.Errorf("guest control volume root must be a dedicated clean absolute path")
	}
	if workspace != expectedWorkspace {
		return fmt.Errorf("guest control protocol version 3 requires the exact %s workspace mount", expectedWorkspace)
	}
	if guestPathWithin(volumeRoot, workspace) {
		return fmt.Errorf("guest control volume identity root must be outside the workspace mount")
	}

	mountInfoPath := filepath.Join(rootPath, "proc", "self", "mountinfo")
	mountInfo, err := readBoundedGuestMountInfo(mountInfoPath)
	if err != nil {
		return err
	}
	if err := verifyGuestControlWorkspaceVolumeSnapshot(manifest, workspace, volumeRoot, mountInfo); err != nil {
		return err
	}
	afterMountInfo, err := readBoundedGuestMountInfo(mountInfoPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(mountInfo, afterMountInfo) {
		return fmt.Errorf("guest mountinfo changed during workspace-volume verification")
	}
	return nil
}

func verifyGuestControlWorkspaceVolumeSnapshot(manifest guestcontrol.Manifest, workspace, volumeRoot string, mountInfo []byte) error {
	volumeInfo, err := inspectGuestDirectoryPath(volumeRoot)
	if err != nil {
		return fmt.Errorf("inspect guest control volume root: %w", err)
	}
	workspaceInfo, err := inspectGuestDirectoryPath(workspace)
	if err != nil {
		return fmt.Errorf("inspect guest control workspace mount: %w", err)
	}
	volumeWorkspace := filepath.Join(volumeRoot, guestVolumeWorkspaceDirectory)
	volumeWorkspaceInfo, err := inspectGuestDirectoryPath(volumeWorkspace)
	if err != nil {
		return fmt.Errorf("inspect guest control volume workspace subdirectory: %w", err)
	}

	entries, err := parseGuestMountInfo(mountInfo)
	if err != nil {
		return fmt.Errorf("parse guest mountinfo: %w", err)
	}
	volumeMount, err := exactGuestMountInfoEntry(entries, volumeRoot)
	if err != nil {
		return fmt.Errorf("verify exact guest volume mount: %w", err)
	}
	workspaceMount, err := exactGuestMountInfoEntry(entries, workspace)
	if err != nil {
		return fmt.Errorf("verify exact guest workspace mount: %w", err)
	}

	rootPath := string(filepath.Separator)
	expectedWorkspaceRoot := filepath.Join(rootPath, guestVolumeWorkspaceDirectory)
	if volumeMount.fsType != "ext4" || volumeMount.root != rootPath {
		return fmt.Errorf("guest control volume root is not an exact whole-filesystem ext4 mount")
	}
	if workspaceMount.fsType != "ext4" || workspaceMount.root != expectedWorkspaceRoot {
		return fmt.Errorf("guest control workspace is not rooted at the volume workspace subdirectory")
	}
	if volumeMount.major != workspaceMount.major || volumeMount.minor != workspaceMount.minor {
		return fmt.Errorf("guest control workspace and volume mounts use different devices")
	}
	if !os.SameFile(volumeWorkspaceInfo, workspaceInfo) {
		return fmt.Errorf("guest control workspace mount is not the exact volume workspace subdirectory")
	}
	if volumeWorkspace != workspace && countGuestMountInfoEntries(entries, volumeWorkspace) != 0 {
		return fmt.Errorf("guest control volume workspace subdirectory is itself overmounted")
	}
	for name, info := range map[string]os.FileInfo{
		"volume root": volumeInfo, "workspace mount": workspaceInfo, "volume workspace subdirectory": volumeWorkspaceInfo,
	} {
		major, minor, deviceErr := guestFileDevice(info)
		if deviceErr != nil {
			return fmt.Errorf("inspect guest control %s device: %w", name, deviceErr)
		}
		if major != volumeMount.major || minor != volumeMount.minor {
			return fmt.Errorf("guest control %s device does not match its mountinfo identity", name)
		}
	}

	identityPath := filepath.Join(volumeRoot, guestVolumeIdentityName)
	if guestPathWithin(identityPath, workspace) {
		return fmt.Errorf("guest control volume identity file is inside the workspace mount")
	}
	if countGuestMountInfoEntries(entries, identityPath) != 0 {
		return fmt.Errorf("guest control volume identity file is overmounted")
	}
	if err := readAndValidateGuestVolumeIdentity(identityPath, manifest, volumeMount.major, volumeMount.minor); err != nil {
		return err
	}
	for path, before := range map[string]os.FileInfo{
		volumeRoot: volumeInfo, workspace: workspaceInfo, volumeWorkspace: volumeWorkspaceInfo,
	} {
		after, inspectErr := inspectGuestDirectoryPath(path)
		if inspectErr != nil || !os.SameFile(before, after) {
			return fmt.Errorf("guest control volume mount path identity changed during verification")
		}
	}
	return nil
}

func inspectGuestDirectoryPath(path string) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("path must be clean and absolute")
	}
	rootPath := string(filepath.Separator)
	current := rootPath
	for _, component := range strings.Split(strings.TrimPrefix(path, rootPath), rootPath) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("path component %s is a symlink", current)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("path is not a non-symlink directory")
	}
	return info, nil
}

func readAndValidateGuestVolumeIdentity(path string, manifest guestcontrol.Manifest, expectedMajor, expectedMinor uint32) error {
	before, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect guest control volume identity: %w", err)
	}
	if !safePrivateGuestVolumeIdentityFile(before) || before.Size() > guestcontrol.MaxMessageBytes {
		return fmt.Errorf("guest control volume identity has unsafe type, ownership, permissions, links, or size")
	}
	major, minor, err := guestFileDevice(before)
	if err != nil || major != expectedMajor || minor != expectedMinor {
		return fmt.Errorf("guest control volume identity is not stored on the exact volume device")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open guest control volume identity: %w", err)
	}
	file := os.NewFile(uintptr(fd), guestVolumeIdentityName)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open guest control volume identity: invalid file descriptor")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !safePrivateGuestVolumeIdentityFile(opened) || !os.SameFile(before, opened) {
		return fmt.Errorf("guest control volume identity changed while opening")
	}
	identity, err := decodeStrictGuestVolumeIdentity(io.LimitReader(file, guestcontrol.MaxMessageBytes+1))
	if err != nil {
		return fmt.Errorf("decode guest control volume identity: %w", err)
	}
	if identity.SchemaVersion != guestVolumeIdentitySchemaVersion || identity.SessionID != manifest.SessionID || identity.VolumeID != manifest.VolumeID {
		return fmt.Errorf("guest control volume identity does not match the exact session volume")
	}
	return nil
}

func decodeStrictGuestVolumeIdentity(reader io.Reader) (guestVolumeIdentity, error) {
	decoder := json.NewDecoder(reader)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return guestVolumeIdentity{}, fmt.Errorf("identity must be one JSON object")
	}
	var identity guestVolumeIdentity
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return guestVolumeIdentity{}, err
		}
		name, ok := token.(string)
		if !ok {
			return guestVolumeIdentity{}, fmt.Errorf("identity object field name is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return guestVolumeIdentity{}, fmt.Errorf("identity object field %q is duplicated", name)
		}
		seen[name] = struct{}{}
		switch name {
		case "schema_version":
			err = decoder.Decode(&identity.SchemaVersion)
		case "session_id":
			err = decoder.Decode(&identity.SessionID)
		case "volume_id":
			err = decoder.Decode(&identity.VolumeID)
		default:
			return guestVolumeIdentity{}, fmt.Errorf("identity object field %q is unknown", name)
		}
		if err != nil {
			return guestVolumeIdentity{}, err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return guestVolumeIdentity{}, fmt.Errorf("identity object is incomplete")
	}
	if len(seen) != 3 {
		return guestVolumeIdentity{}, fmt.Errorf("identity object fields are incomplete")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("trailing JSON value")
		}
		return guestVolumeIdentity{}, err
	}
	return identity, nil
}

func safePrivateGuestVolumeIdentityFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func readBoundedGuestMountInfo(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open guest mountinfo: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, guestMountInfoMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read guest mountinfo: %w", err)
	}
	if len(data) == 0 || len(data) > guestMountInfoMaxBytes {
		return nil, fmt.Errorf("guest mountinfo is empty or exceeds its bound")
	}
	return data, nil
}

func parseGuestMountInfo(data []byte) ([]guestMountInfoEntry, error) {
	if len(data) == 0 || len(data) > guestMountInfoMaxBytes {
		return nil, fmt.Errorf("mountinfo is empty or exceeds its bound")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), guestcontrol.MaxMessageBytes)
	entries := make([]guestMountInfoEntry, 0)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index := 6; index < len(fields); index++ {
			if fields[index] == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || len(fields) < separator+4 {
			return nil, fmt.Errorf("mountinfo line has invalid framing")
		}
		major, minor, err := parseGuestMountDevice(fields[2])
		if err != nil {
			return nil, err
		}
		root, err := decodeGuestMountInfoPath(fields[3])
		if err != nil {
			return nil, err
		}
		mountPoint, err := decodeGuestMountInfoPath(fields[4])
		if err != nil {
			return nil, err
		}
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(mountPoint) || filepath.Clean(mountPoint) != mountPoint {
			return nil, fmt.Errorf("mountinfo contains an unclean or non-absolute path")
		}
		entries = append(entries, guestMountInfoEntry{major: major, minor: minor, root: root, mountPoint: mountPoint, fsType: fields[separator+1]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("mountinfo contains no entries")
	}
	return entries, nil
}

func parseGuestMountDevice(value string) (uint32, uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, fmt.Errorf("mountinfo device identity is malformed")
	}
	major, majorErr := strconv.ParseUint(parts[0], 10, 32)
	minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
	if majorErr != nil || minorErr != nil {
		return 0, 0, fmt.Errorf("mountinfo device identity is malformed")
	}
	return uint32(major), uint32(minor), nil
}

func decodeGuestMountInfoPath(value string) (string, error) {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", fmt.Errorf("mountinfo path contains a truncated escape")
		}
		escape := value[index+1 : index+4]
		switch escape {
		case "040":
			decoded.WriteByte(' ')
		case "011":
			decoded.WriteByte('\t')
		case "012":
			decoded.WriteByte('\n')
		case "134":
			decoded.WriteByte('\\')
		default:
			return "", fmt.Errorf("mountinfo path contains an unsupported escape")
		}
		index += 3
	}
	if strings.ContainsRune(decoded.String(), '\x00') {
		return "", fmt.Errorf("mountinfo path contains NUL")
	}
	return decoded.String(), nil
}

func exactGuestMountInfoEntry(entries []guestMountInfoEntry, path string) (guestMountInfoEntry, error) {
	var exact guestMountInfoEntry
	for _, entry := range entries {
		if entry.mountPoint == path {
			exact = entry
		}
	}
	matches := countGuestMountInfoEntries(entries, path)
	if matches != 1 {
		return guestMountInfoEntry{}, fmt.Errorf("mountpoint %s has %d exact entries, want 1", path, matches)
	}
	return exact, nil
}

func countGuestMountInfoEntries(entries []guestMountInfoEntry, path string) int {
	matches := 0
	for _, entry := range entries {
		if entry.mountPoint == path {
			matches++
		}
	}
	return matches
}

func guestFileDevice(info os.FileInfo) (uint32, uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("Linux file identity is unavailable")
	}
	return unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)), nil
}

func guestPathWithin(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(path, prefix)
}
