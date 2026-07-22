//go:build linux

// agentsh-bwrap-adapter implements the reviewed Bubblewrap 0.11.2 semantic
// subset. It never mounts: it creates fresh descendant namespaces, submits a
// plan through the injected broker channel, then execs the payload itself.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/agentsh/agentsh/internal/composition"
	"golang.org/x/sys/unix"
)

const internalChildArg = "--agentsh-composition-internal-child-v1"

func main() {
	var err error
	if len(os.Args) == 3 && os.Args[1] == internalChildArg {
		err = runChild(os.Args[2])
	} else {
		err = runAdapter(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-bwrap-adapter: %v\n", err)
		os.Exit(125)
	}
}

func runAdapter(args []string) error {
	if _, err := unix.FcntlInt(uintptr(composition.InjectFD), unix.F_GETFD, 0); err != nil {
		return fmt.Errorf("missing broker channel: %w", err)
	}
	// The executable fd was needed only for the race-tolerant exec rewrite.
	_ = unix.Close(composition.AdapterFD)

	plan, err := composition.ParseBubblewrap(args)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("encode plan: %w", err)
	}
	if len(encoded) > 1024*1024 {
		return &composition.Error{Code: "E_COMPOSITION_LIMIT_EXCEEDED", Message: "encoded plan exceeds 1 MiB"}
	}

	planReader, planWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create plan pipe: %w", err)
	}
	brokerFile := os.NewFile(uintptr(composition.InjectFD), "agentsh-composition-broker")
	if brokerFile == nil {
		_ = planReader.Close()
		_ = planWriter.Close()
		return errors.New("open broker channel")
	}

	selfLink := filepath.Join(string(filepath.Separator), "proc", "self", "exe")
	self, err := os.Readlink(selfLink)
	if err != nil {
		_ = planReader.Close()
		_ = planWriter.Close()
		_ = brokerFile.Close()
		return fmt.Errorf("resolve adapter executable identity: %w", err)
	}
	if !filepath.IsAbs(self) || strings.HasSuffix(self, " (deleted)") {
		_ = planReader.Close()
		_ = planWriter.Close()
		_ = brokerFile.Close()
		return fmt.Errorf("resolve adapter executable identity: invalid target %q", self)
	}
	launcher := filepath.Join(filepath.Dir(self), "agentsh-composition-ns-launcher")
	namespaceFlags := uintptr(unix.CLONE_NEWNS)
	if plan.UnsharePID {
		namespaceFlags |= unix.CLONE_NEWPID
	}
	if plan.UnshareIPC {
		namespaceFlags |= unix.CLONE_NEWIPC
	}
	if plan.UnshareUTS {
		namespaceFlags |= unix.CLONE_NEWUTS
	}
	if plan.UnshareCgroup {
		namespaceFlags |= unix.CLONE_NEWCGROUP
	}
	uid, gid := os.Geteuid(), os.Getegid()
	if uid != 1 || gid != 1 {
		_ = planReader.Close()
		_ = planWriter.Close()
		_ = brokerFile.Close()
		return &composition.Error{Code: "E_COMPOSITION_NAMESPACE_INVALID", Message: "composition requires admitted namespace identity 1"}
	}
	newSession := "0"
	if plan.NewSession {
		newSession = "1"
	}
	command := exec.Command(launcher, self, fmt.Sprintf("%d", namespaceFlags), newSession, fmt.Sprintf("%d", uid), fmt.Sprintf("%d", gid))
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = os.Environ()
	command.ExtraFiles = []*os.File{brokerFile, planReader}

	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		_ = planReader.Close()
		_ = planWriter.Close()
		_ = brokerFile.Close()
		return fmt.Errorf("create descendant namespaces via %q: %w", self, err)
	}
	_ = planReader.Close()
	_ = brokerFile.Close()
	_ = unix.Close(composition.InjectFD)
	if _, err := planWriter.Write(encoded); err != nil {
		_ = planWriter.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return fmt.Errorf("write child plan: %w", err)
	}
	_ = planWriter.Close()

	signals := make(chan os.Signal, 8)
	signal.Notify(signals)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range signals {
			_ = command.Process.Signal(sig)
		}
	}()
	waitErr := command.Wait()
	signal.Stop(signals)
	close(signals)
	<-done
	return propagateProcessStatus(waitErr)
}

func propagateProcessStatus(waitErr error) error {
	if waitErr == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() {
				_ = unix.Kill(os.Getpid(), status.Signal())
				return waitErr
			}
			os.Exit(status.ExitStatus())
		}
	}
	return waitErr
}

func verifyPayloadPrivileges() error {
	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || noNewPrivileges != 1 {
		return &composition.Error{Code: "E_COMPOSITION_NAMESPACE_INVALID", Message: "no_new_privs was not retained"}
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("read payload capabilities: %w", err)
	}
	for _, capabilities := range data {
		if capabilities.Effective != 0 || capabilities.Permitted != 0 || capabilities.Inheritable != 0 {
			return &composition.Error{Code: "E_COMPOSITION_NAMESPACE_INVALID", Message: "nested payload retained capabilities"}
		}
	}
	return nil
}

func runChild(nonce string) error {
	decodedNonce, err := hex.DecodeString(nonce)
	if err != nil || len(decodedNonce) != 16 {
		return &composition.Error{Code: "E_COMPOSITION_REQUESTER_CHANGED", Message: "invalid one-shot broker nonce"}
	}
	if err := verifyPayloadPrivileges(); err != nil {
		return err
	}
	brokerFD := composition.BrokerFD
	planFile := os.NewFile(uintptr(composition.PlanFD), "agentsh-composition-plan")
	if planFile == nil {
		return errors.New("missing plan descriptor")
	}
	encoded, err := io.ReadAll(io.LimitReader(planFile, 1024*1024+1))
	_ = planFile.Close()
	_ = unix.Close(composition.PlanFD)
	if err != nil {
		return fmt.Errorf("read plan: %w", err)
	}
	if len(encoded) > 1024*1024 {
		return &composition.Error{Code: "E_COMPOSITION_LIMIT_EXCEEDED", Message: "plan exceeds 1 MiB"}
	}
	var plan composition.Plan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}
	plan.Nonce = nonce
	encoded, err = json.Marshal(plan)
	if err != nil {
		return fmt.Errorf("encode nonce-bound plan: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(brokerFD), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return fmt.Errorf("mark broker channel close-on-exec: %w", err)
	}
	if _, err := unix.SendmsgN(brokerFD, encoded, nil, nil, 0); err != nil {
		return fmt.Errorf("send broker plan: %w", err)
	}
	responseBuffer := make([]byte, 64*1024)
	n, _, err := unix.Recvfrom(brokerFD, responseBuffer, 0)
	if err != nil {
		return fmt.Errorf("receive broker response: %w", err)
	}
	_ = unix.Close(brokerFD)
	var response composition.Response
	if err := json.Unmarshal(responseBuffer[:n], &response); err != nil {
		return fmt.Errorf("decode broker response: %w", err)
	}
	if !response.OK {
		return &composition.Error{Code: response.Code, Message: response.Message}
	}

	if plan.UID != nil && *plan.UID != os.Geteuid() {
		return &composition.Error{Code: "E_COMPOSITION_OPTION_UNSUPPORTED", Message: "requested UID is not mapped in the descendant namespace"}
	}
	if plan.GID != nil && *plan.GID != os.Getegid() {
		return &composition.Error{Code: "E_COMPOSITION_OPTION_UNSUPPORTED", Message: "requested GID is not mapped in the descendant namespace"}
	}
	if err := verifyPayloadPrivileges(); err != nil {
		return err
	}
	if plan.Cwd != "" {
		if err := os.Chdir(plan.Cwd); err != nil {
			return fmt.Errorf("chdir %s: %w", plan.Cwd, err)
		}
	}
	environment := applyEnvironment(plan)
	command, err := lookPath(plan.Command[0], environment)
	if err != nil {
		return err
	}
	if plan.AsPID1 {
		if err := syscall.Exec(command, plan.Command, environment); err != nil {
			return fmt.Errorf("exec PID-1 payload %q: %w", command, err)
		}
		return nil
	}
	payload := exec.Command(command, plan.Command[1:]...)
	payload.Args = append([]string(nil), plan.Command...)
	payload.Env = environment
	payload.Stdin = os.Stdin
	payload.Stdout = os.Stdout
	payload.Stderr = os.Stderr
	payload.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := payload.Start(); err != nil {
		return fmt.Errorf("start payload %q: %w", command, err)
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for received := range signals {
			_ = payload.Process.Signal(received)
		}
	}()
	waitErr := payload.Wait()
	signal.Stop(signals)
	close(signals)
	<-done
	return propagateProcessStatus(waitErr)
}

func applyEnvironment(plan composition.Plan) []string {
	values := make(map[string]string)
	if !plan.ClearEnv {
		for _, entry := range os.Environ() {
			if key, value, ok := strings.Cut(entry, "="); ok {
				values[key] = value
			}
		}
	}
	for _, key := range plan.UnsetEnv {
		delete(values, key)
	}
	for key, value := range plan.SetEnv {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func lookPath(command string, environment []string) (string, error) {
	if strings.ContainsRune(command, filepath.Separator) {
		return command, nil
	}
	pathValue := ""
	for _, entry := range environment {
		if strings.HasPrefix(entry, "PATH=") {
			pathValue = strings.TrimPrefix(entry, "PATH=")
			break
		}
	}
	for _, directory := range filepath.SplitList(pathValue) {
		candidate := filepath.Join(directory, command)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("payload executable %q not found in PATH", command)
}
