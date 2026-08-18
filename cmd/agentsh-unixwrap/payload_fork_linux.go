//go:build linux && cgo

package main

/*
#cgo CFLAGS: -std=c11 -Wall -Wextra -Werror
#include <errno.h>
#include <stdlib.h>
#include "payload_child_linux.h"
static int agentsh_payload_errno(void) { return errno; }
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	childAttestMagic = 0x54544143
	childStatusMagic = 0x53544143
	childMessageSize = 32
)

type payloadForkConfig struct {
	controlFD        int
	brokerParentFD   int
	brokerTransferFD int
	commandJail      bool
	waitKillable     bool
	baseProgram      []byte
	frozenProgram    []byte
	execPath         string
	argv             []string
	env              []string
}

type payloadChild struct {
	pid  int
	sync *os.File
}

type payloadAttestation struct {
	PID        int
	TID        int
	SecureBits int
	NoNewPrivs int
}

func forkPayload(config payloadForkConfig) (*payloadChild, error) {
	if config.controlFD < 3 || config.execPath == "" || len(config.argv) == 0 || len(config.baseProgram) == 0 {
		return nil, errors.New("incomplete payload fork configuration")
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create payload parity channel: %w", err)
	}
	parentSync := os.NewFile(uintptr(fds[0]), "payload-parity-parent")
	if parentSync == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return nil, errors.New("retain payload parity parent")
	}

	base := C.CBytes(config.baseProgram)
	if base == nil {
		parentSync.Close()
		_ = unix.Close(fds[1])
		return nil, errors.New("allocate payload filter")
	}
	defer C.free(base)
	var frozen unsafe.Pointer
	if len(config.frozenProgram) > 0 {
		frozen = C.CBytes(config.frozenProgram)
		if frozen == nil {
			parentSync.Close()
			_ = unix.Close(fds[1])
			return nil, errors.New("allocate frozen payload filter")
		}
		defer C.free(frozen)
	}
	execPath := C.CString(config.execPath)
	if execPath == nil {
		parentSync.Close()
		_ = unix.Close(fds[1])
		return nil, errors.New("allocate payload executable path")
	}
	defer C.free(unsafe.Pointer(execPath))

	argv, freeArgv, err := cStringVector(config.argv)
	if err != nil {
		parentSync.Close()
		_ = unix.Close(fds[1])
		return nil, err
	}
	defer freeArgv()
	env, freeEnv, err := cStringVector(config.env)
	if err != nil {
		parentSync.Close()
		_ = unix.Close(fds[1])
		return nil, err
	}
	defer freeEnv()

	spec := C.struct_agentsh_payload_spec{
		control_fd:          C.int(config.controlFD),
		sync_parent_fd:      C.int(fds[0]),
		sync_child_fd:       C.int(fds[1]),
		broker_parent_fd:    C.int(config.brokerParentFD),
		broker_transfer_fd:  C.int(config.brokerTransferFD),
		expected_parent_pid: C.int(unix.Getpid()),
		command_jail:        boolCInt(config.commandJail),
		want_wait_killable:  boolCInt(config.waitKillable),
		base_program:        (*C.uchar)(base),
		base_program_size:   C.size_t(len(config.baseProgram)),
		frozen_program:      (*C.uchar)(frozen),
		frozen_program_size: C.size_t(len(config.frozenProgram)),
		exec_path:           execPath,
		argv:                argv,
		envp:                env,
	}
	pid := C.agentsh_fork_payload(&spec)
	callErrno := unix.Errno(C.agentsh_payload_errno())
	_ = unix.Close(fds[1])
	if pid < 0 {
		parentSync.Close()
		if callErrno == 0 {
			callErrno = unix.EIO
		}
		return nil, fmt.Errorf("fork payload: %w", callErrno)
	}
	return &payloadChild{pid: int(pid), sync: parentSync}, nil
}

func boolCInt(value bool) C.int {
	if value {
		return 1
	}
	return 0
}

func cStringVector(values []string) (**C.char, func(), error) {
	count := len(values) + 1
	memory := C.calloc(C.size_t(count), C.size_t(unsafe.Sizeof(uintptr(0))))
	if memory == nil {
		return nil, nil, errors.New("allocate C string vector")
	}
	vector := unsafe.Slice((**C.char)(memory), count)
	allocated := make([]unsafe.Pointer, 0, len(values))
	cleanup := func() {
		for _, value := range allocated {
			C.free(value)
		}
		C.free(memory)
	}
	for index, value := range values {
		cstring := C.CString(value)
		if cstring == nil {
			cleanup()
			return nil, nil, errors.New("allocate C string")
		}
		vector[index] = cstring
		allocated = append(allocated, unsafe.Pointer(cstring))
	}
	vector[len(values)] = nil
	return (**C.char)(memory), cleanup, nil
}

func (p *payloadChild) Close() error {
	if p == nil || p.sync == nil {
		return nil
	}
	err := p.sync.Close()
	p.sync = nil
	return err
}

func (p *payloadChild) readAttestation() (payloadAttestation, error) {
	packet, err := p.readMessage()
	if err != nil {
		return payloadAttestation{}, err
	}
	if littleUint32(packet[0:4]) != childAttestMagic {
		return payloadAttestation{}, errors.New("payload omitted context attestation")
	}
	return payloadAttestation{
		PID:        int(littleUint32(packet[8:12])),
		TID:        int(littleUint32(packet[12:16])),
		SecureBits: int(littleUint32(packet[16:20])),
		NoNewPrivs: int(littleUint32(packet[20:24])),
	}, nil
}

func (p *payloadChild) sendLookupReadiness(ready bool) error {
	value := byte(0)
	if ready {
		value = 1
	}
	return writeExactByte(p.sync, value)
}

func (p *payloadChild) waitHandoffStatus() error {
	packet, err := p.readMessage()
	if err != nil {
		return err
	}
	if littleUint32(packet[0:4]) != childStatusMagic {
		return errors.New("payload returned invalid handoff status")
	}
	if errno := littleUint32(packet[8:12]); errno != 0 {
		return fmt.Errorf("payload setup failed: %w", unix.Errno(errno))
	}
	return nil
}

func (p *payloadChild) release() error {
	return writeExactByte(p.sync, 'X')
}

func (p *payloadChild) readMessage() ([]byte, error) {
	if p == nil || p.sync == nil {
		return nil, errors.New("payload parity channel is unavailable")
	}
	packet := make([]byte, childMessageSize)
	if _, err := io.ReadFull(p.sync, packet); err != nil {
		return nil, err
	}
	if littleUint16(packet[4:6]) != 1 || littleUint16(packet[6:8]) != childMessageSize {
		return nil, errors.New("invalid payload parity message")
	}
	return packet, nil
}

func writeExactByte(file *os.File, value byte) error {
	if file == nil {
		return errors.New("nil control file")
	}
	n, err := file.Write([]byte{value})
	if err != nil {
		return err
	}
	if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func littleUint16(source []byte) uint16 {
	return uint16(source[0]) | uint16(source[1])<<8
}

func littleUint32(source []byte) uint32 {
	return uint32(source[0]) | uint32(source[1])<<8 | uint32(source[2])<<16 | uint32(source[3])<<24
}
