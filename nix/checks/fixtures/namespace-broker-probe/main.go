//go:build linux

// namespace-broker-probe is a NixOS-VM-only payload/server fixture. It compares
// a generic seccomp-notify mount broker with a small bwrap-argv-style semantic
// broker while the requesting payload remains in an inherited Landlock domain.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type mountRequest struct {
	Source string `json:"source"`
	Root   string `json:"root"`
}

type brokerResponse struct {
	Error string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: %s generic|generic-child|semantic|semantic-child|semantic-server|verify", filepath.Base(os.Args[0]))
	}
	var err error
	switch os.Args[1] {
	case "generic":
		err = runGeneric(os.Args[2:])
	case "generic-child":
		err = runGenericChild(os.Args[2:])
	case "semantic":
		err = runSemantic(os.Args[2:])
	case "semantic-child":
		err = runSemanticChild(os.Args[2:])
	case "semantic-server":
		err = runSemanticServer(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func runGeneric(args []string) error {
	fs := flag.NewFlagSet("generic", flag.ContinueOnError)
	source := fs.String("source", "", "approved read-only bind source")
	root := fs.String("root", "", "broker destination root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateAbsolute(*source, *root); err != nil {
		return err
	}
	if err := prepareDestinations(*root); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return runNamespaced(self, []string{"generic-child", "--source", *source, "--root", *root})
}

func runGenericChild(args []string) error {
	fs := flag.NewFlagSet("generic-child", flag.ContinueOnError)
	source := fs.String("source", "", "approved source")
	root := fs.String("root", "", "destination root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateAbsolute(*source, *root); err != nil {
		return err
	}
	if err := unix.Mount(*source, filepath.Join(*root, "bind"), "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("brokered bind request: %w", err)
	}
	if err := unix.Mount("tmpfs", filepath.Join(*root, "tmpfs"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=64k"); err != nil {
		return fmt.Errorf("brokered tmpfs request: %w", err)
	}
	if err := unix.Mount("proc", filepath.Join(*root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "hidepid=2"); err != nil {
		return fmt.Errorf("brokered proc request: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(self, []string{self, "verify", "--mode", "generic", "--source", *source, "--root", *root}, os.Environ())
}

func runSemantic(args []string) error {
	fs := flag.NewFlagSet("semantic", flag.ContinueOnError)
	socket := fs.String("socket", "", "semantic broker socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	request, command, err := parseBwrapSubset(fs.Args())
	if err != nil {
		return err
	}
	if !filepath.IsAbs(*socket) {
		return errors.New("--socket must be absolute")
	}
	if err := prepareDestinations(request.Root); err != nil {
		return err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := []string{"semantic-child", "--socket", *socket, "--request", string(encoded), "--"}
	childArgs = append(childArgs, command...)
	return runNamespaced(self, childArgs)
}

func parseBwrapSubset(args []string) (mountRequest, []string, error) {
	var request mountRequest
	seenTmpfs := false
	seenProc := false
	for len(args) > 0 {
		switch args[0] {
		case "--ro-bind":
			if len(args) < 3 {
				return request, nil, errors.New("--ro-bind needs SOURCE DEST")
			}
			request.Source = args[1]
			if filepath.Base(args[2]) != "bind" {
				return request, nil, errors.New("probe --ro-bind destination must end in /bind")
			}
			request.Root = filepath.Dir(args[2])
			args = args[3:]
		case "--tmpfs":
			if len(args) < 2 || request.Root == "" || args[1] != filepath.Join(request.Root, "tmpfs") {
				return request, nil, errors.New("probe --tmpfs must target ROOT/tmpfs after --ro-bind")
			}
			seenTmpfs = true
			args = args[2:]
		case "--proc":
			if len(args) < 2 || request.Root == "" || args[1] != filepath.Join(request.Root, "proc") {
				return request, nil, errors.New("probe --proc must target ROOT/proc after --ro-bind")
			}
			seenProc = true
			args = args[2:]
		case "--":
			args = args[1:]
			if request.Source == "" || request.Root == "" || !seenTmpfs || !seenProc || len(args) == 0 {
				return request, nil, errors.New("incomplete semantic broker probe command")
			}
			if err := validateAbsolute(request.Source, request.Root, args[0]); err != nil {
				return request, nil, err
			}
			return request, args, nil
		default:
			return request, nil, fmt.Errorf("unsupported probe bwrap argument %q", args[0])
		}
	}
	return request, nil, errors.New("missing -- and payload command")
}

func runSemanticChild(args []string) error {
	fs := flag.NewFlagSet("semantic-child", flag.ContinueOnError)
	socket := fs.String("socket", "", "semantic broker socket")
	requestJSON := fs.String("request", "", "validated semantic request")
	if err := fs.Parse(args); err != nil {
		return err
	}
	command := fs.Args()
	if len(command) == 0 || !filepath.IsAbs(command[0]) {
		return errors.New("semantic child requires an absolute payload command")
	}
	var request mountRequest
	if err := json.Unmarshal([]byte(*requestJSON), &request); err != nil {
		return err
	}
	connection, err := net.Dial("unix", *socket)
	if err != nil {
		return fmt.Errorf("connect semantic broker: %w", err)
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		_ = connection.Close()
		return err
	}
	var response brokerResponse
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&response); err != nil {
		_ = connection.Close()
		return fmt.Errorf("read semantic broker response: %w", err)
	}
	_ = connection.Close()
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return syscall.Exec(command[0], command, os.Environ())
}

func runSemanticServer(args []string) error {
	fs := flag.NewFlagSet("semantic-server", flag.ContinueOnError)
	socket := fs.String("socket", "", "broker socket")
	helper := fs.String("helper", "", "mount helper")
	source := fs.String("source", "", "only approved source")
	root := fs.String("root", "", "only approved destination root")
	ready := fs.String("ready", "", "readiness marker")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateAbsolute(*socket, *helper, *source, *root, *ready); err != nil {
		return err
	}
	_ = os.Remove(*socket)
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(*socket)
	if err := os.WriteFile(*ready, []byte("ready\n"), 0o600); err != nil {
		return err
	}
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	pid, err := peerPID(connection)
	if err != nil {
		return err
	}
	var request mountRequest
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&request); err != nil {
		return err
	}
	response := brokerResponse{}
	if filepath.Clean(request.Source) != filepath.Clean(*source) || filepath.Clean(request.Root) != filepath.Clean(*root) {
		response.Error = "semantic broker rejected source or destination"
	} else if err := performMountSet(*helper, pid, request); err != nil {
		response.Error = err.Error()
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return err
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	return nil
}

func peerPID(connection net.Conn) (int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("semantic broker connection is not Unix")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	return int(credentials.Pid), nil
}

func performMountSet(helper string, pid int, request mountRequest) error {
	bind := filepath.Join(request.Root, "bind")
	if err := runMountHelper(helper, pid, request.Source, bind, "", uint64(unix.MS_BIND), ""); err != nil {
		return err
	}
	readonly := uint64(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
	if err := runMountHelper(helper, pid, "", bind, "", readonly, ""); err != nil {
		return err
	}
	if err := runMountHelper(helper, pid, "tmpfs", filepath.Join(request.Root, "tmpfs"), "tmpfs", uint64(unix.MS_NOSUID|unix.MS_NODEV), "size=64k"); err != nil {
		return err
	}
	return runMountHelper(helper, pid, "proc", filepath.Join(request.Root, "proc"), "proc", uint64(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC), "hidepid=2")
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	mode := fs.String("mode", "", "generic or semantic")
	source := fs.String("source", "", "source containing marker")
	root := fs.String("root", "", "mounted root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode != "generic" && *mode != "semantic" {
		return errors.New("invalid verification mode")
	}
	if err := validateAbsolute(*source, *root); err != nil {
		return err
	}
	marker, err := os.ReadFile(filepath.Join(*root, "bind", "marker"))
	if err != nil || strings.TrimSpace(string(marker)) != "broker-source" {
		return fmt.Errorf("read brokered bind marker: value=%q error=%v", marker, err)
	}
	if err := os.WriteFile(filepath.Join(*root, "bind", "must-stay-read-only"), []byte("bad"), 0o600); err == nil {
		return errors.New("read-only source gained write authority at destination")
	}
	if err := os.WriteFile(filepath.Join(*root, "tmpfs", "scratch"), []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("write brokered tmpfs: %w", err)
	}
	status, err := os.ReadFile(filepath.Join(*root, "proc", "1", "status"))
	if err != nil || !strings.Contains(string(status), "NSpid:") {
		return fmt.Errorf("read brokered private proc: %w", err)
	}
	forbidden := filepath.Join(*root, "forbidden")
	mountErr := unix.Mount("tmpfs", forbidden, "tmpfs", 0, "size=4k")
	if !errors.Is(mountErr, unix.EPERM) && !errors.Is(mountErr, unix.EACCES) {
		return fmt.Errorf("unbrokered mount result=%v, want EPERM-class denial", mountErr)
	}
	result := map[string]any{
		"stage":                   "landlock_broker_composition",
		"result":                  "pass",
		"mode":                    *mode,
		"bind_preserved_readonly": true,
		"tmpfs_writable":          true,
		"private_proc":            true,
		"raw_mount_denied":        true,
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func runNamespaced(executable string, args []string) error {
	command := exec.Command(executable, args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	uid := os.Geteuid()
	gid := os.Getegid()
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	if err := command.Run(); err != nil {
		return fmt.Errorf("run descendant namespace payload: %w", err)
	}
	return nil
}

func prepareDestinations(root string) error {
	for _, name := range []string{"bind", "tmpfs", "proc", "forbidden"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func runMountHelper(helper string, pid int, source, target, filesystem string, flags uint64, data string) error {
	files := make([]*os.File, 0, 3)
	for _, namespace := range []string{"user", "pid", "mnt"} {
		file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "ns", namespace))
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return fmt.Errorf("open peer %s namespace: %w", namespace, err)
		}
		files = append(files, file)
	}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	optional := func(value string) string {
		if value == "" {
			return "-"
		}
		return value
	}
	command := exec.Command(helper, optional(source), target, optional(filesystem), strconv.FormatUint(flags, 10), optional(data))
	command.ExtraFiles = files
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount helper failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func validateAbsolute(paths ...string) error {
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("path must be absolute: %q", path)
		}
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "namespace-broker-probe: "+format+"\n", args...)
	os.Exit(1)
}
