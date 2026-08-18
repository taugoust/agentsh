//go:build linux && cgo

package api

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/wraphandoff"
)

func TestAcceptNotifyFDLineageBindsExactWrapperAndPayload(t *testing.T) {
	app, manager := newTestAppForWrap(t, &config.Config{})
	sessionValue, err := manager.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatal(err)
	}

	wrapper := exec.Command("sh", "-c", "read ready; sleep 30 & echo $!; wait")
	wrapperInput, err := wrapper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	wrapperOutput, err := wrapper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := wrapper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = wrapper.Process.Kill()
		_ = wrapper.Wait()
	}()

	directory := t.TempDir()
	socketPath := filepath.Join(directory, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	ctx := context.WithValue(context.Background(), wrapSeccompConfigContextKey{}, seccompWrapperConfig{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(ctx, listener, socketPath, sessionValue.ID, sessionValue, false, os.Geteuid(), false, nil)
	}()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	unixConnection := connection.(*net.UnixConn)
	defer unixConnection.Close()
	if err := wraphandoff.SendPrelude(unixConnection, wraphandoff.Metadata{WrapperPID: wrapper.Process.Pid}); err != nil {
		t.Fatal(err)
	}
	if err := wraphandoff.ReadStatus(unixConnection); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapperInput.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(wrapperOutput).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	payloadPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}

	previous := startNotifyHandlerForWrapHook
	captured := make(chan wrapLineageContext, 1)
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD, composition *os.File, _ string, _ *App, _ bool, gotWrapper int, _ *session.Session, _ func() error) error {
		defer notifyFD.Close()
		if gotWrapper != wrapper.Process.Pid {
			t.Fatalf("wrapper pid = %d, want %d", gotWrapper, wrapper.Process.Pid)
		}
		lineage, _ := ctx.Value(wrapLineageContextKey{}).(wrapLineageContext)
		captured <- lineage
		return nil
	}
	t.Cleanup(func() { startNotifyHandlerForWrapHook = previous })

	notifyR, notifyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer notifyR.Close()
	defer notifyW.Close()
	if err := wraphandoff.SendPayloadHandoff(unixConnection, int(notifyR.Fd()), -1, -1, wraphandoff.Metadata{
		WrapperPID: wrapper.Process.Pid, PayloadPID: payloadPID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := wraphandoff.ReadStatus(unixConnection); err != nil {
		t.Fatal(err)
	}
	select {
	case lineage := <-captured:
		if lineage.PayloadPID != payloadPID || lineage.FileLookupBroker != nil {
			t.Fatalf("lineage = %+v", lineage)
		}
	case <-time.After(time.Second):
		t.Fatal("notify handler did not receive lineage")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lineage accept did not finish")
	}
}
