package filelookup

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ProtocolVersion uint16 = 1

	MaxPathBytes   = 4095
	MaxLabelBytes  = 4096
	MaxPacketBytes = 128 + MaxPathBytes + MaxLabelBytes

	helloMagic   uint32 = 0x4b4f4f4c // "LOOK" in little endian on the wire
	requestMagic uint32 = 0x51524c46 // "FLRQ"
	resultMagic  uint32 = 0x53524c46 // "FLRS"

	helloSize         = 32
	requestHeaderSize = 104
	resultSize        = 32
)

// Operation is the broker-validated lookup shape. The wrapper derives this
// from a positively eligible syscall; the native worker never accepts an
// arbitrary syscall number from the supervisor.
type Operation uint16

const (
	OperationInvalid Operation = iota
	OperationOpen
	OperationOpenat2
	OperationStatx
	OperationFstatat
	OperationFaccessat
	OperationReadlinkMetadata
)

// Class is the compact native protocol form of the public lookup classes.
type Class uint16

const (
	ClassUnknown Class = iota
	ClassExists
	ClassAbsent
	ClassInaccessible
	ClassNotDirectory
	ClassSymlinkLoop
	ClassInvalid
	ClassStale
)

// Reason is intentionally a closed enum. No helper-provided strings cross the
// process boundary.
type Reason uint16

const (
	ReasonNone Reason = iota
	ReasonUnavailable
	ReasonIneligible
	ReasonAdmission
	ReasonTimeout
	ReasonProtocol
	ReasonWorkerCrash
	ReasonWorkerUnavailable
	ReasonTaskStale
	ReasonLineageMismatch
	ReasonNamespaceMismatch
	ReasonRootMismatch
	ReasonCredentialMismatch
	ReasonCapabilityMismatch
	ReasonSecurityLabel
	ReasonCgroupMismatch
	ReasonContextUnavailable
	ReasonPIDSensitiveLSM
	ReasonFUSE
	ReasonMagicLink
	ReasonDirectoryUnavailable
	ReasonSymlinkContext
	ReasonErrno
)

// Hello is queued on the private broker socket before its endpoint is handed
// off. Limits are capability metadata, not caller-controlled configuration.
type Hello struct {
	WrapperPID      uint32
	PayloadPID      uint32
	MaxPacketBytes  uint32
	WorkerTimeoutMS uint32
}

func EncodeHello(h Hello) []byte {
	buf := make([]byte, helloSize)
	binary.LittleEndian.PutUint32(buf[0:4], helloMagic)
	binary.LittleEndian.PutUint16(buf[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(helloSize))
	binary.LittleEndian.PutUint32(buf[8:12], h.WrapperPID)
	binary.LittleEndian.PutUint32(buf[12:16], h.PayloadPID)
	binary.LittleEndian.PutUint32(buf[16:20], h.MaxPacketBytes)
	binary.LittleEndian.PutUint32(buf[20:24], h.WorkerTimeoutMS)
	return buf
}

func DecodeHello(buf []byte) (Hello, error) {
	if len(buf) != helloSize || binary.LittleEndian.Uint32(buf[0:4]) != helloMagic || binary.LittleEndian.Uint16(buf[4:6]) != ProtocolVersion || binary.LittleEndian.Uint16(buf[6:8]) != helloSize {
		return Hello{}, errors.New("invalid file lookup broker hello")
	}
	h := Hello{
		WrapperPID:      binary.LittleEndian.Uint32(buf[8:12]),
		PayloadPID:      binary.LittleEndian.Uint32(buf[12:16]),
		MaxPacketBytes:  binary.LittleEndian.Uint32(buf[16:20]),
		WorkerTimeoutMS: binary.LittleEndian.Uint32(buf[20:24]),
	}
	if h.WrapperPID == 0 || h.PayloadPID == 0 || h.MaxPacketBytes < requestHeaderSize || h.MaxPacketBytes > MaxPacketBytes || h.WorkerTimeoutMS == 0 || h.WorkerTimeoutMS > 5000 {
		return Hello{}, errors.New("invalid file lookup broker capability limits")
	}
	return h, nil
}

// Request is the fixed-width lookup context plus bounded pathname/label data.
type Request struct {
	ID            uint64
	HostTID       uint32
	NamespaceTID  uint32
	StartTime     uint64
	Operation     Operation
	DirFD         int32
	OpenFlags     uint64
	OpenMode      uint64
	ResolveFlags  uint64
	LookupFlags   uint32
	StatMask      uint32
	AccessMode    uint32
	AccessFlags   uint32
	ReadlinkLen   uint64
	Path          string
	ExpectedLabel string
}

func EncodeRequest(r Request) ([]byte, error) {
	if r.ID == 0 || r.HostTID == 0 || r.NamespaceTID == 0 || r.StartTime == 0 || r.Operation <= OperationInvalid || r.Operation > OperationReadlinkMetadata {
		return nil, errors.New("invalid file lookup request identity")
	}
	if len(r.Path) == 0 || len(r.Path) > MaxPathBytes || len(r.ExpectedLabel) > MaxLabelBytes {
		return nil, errors.New("file lookup request exceeds protocol bounds")
	}
	buf := make([]byte, requestHeaderSize+len(r.Path)+len(r.ExpectedLabel))
	binary.LittleEndian.PutUint32(buf[0:4], requestMagic)
	binary.LittleEndian.PutUint16(buf[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(requestHeaderSize))
	binary.LittleEndian.PutUint64(buf[8:16], r.ID)
	binary.LittleEndian.PutUint32(buf[16:20], r.HostTID)
	binary.LittleEndian.PutUint32(buf[20:24], r.NamespaceTID)
	binary.LittleEndian.PutUint64(buf[24:32], r.StartTime)
	binary.LittleEndian.PutUint16(buf[32:34], uint16(r.Operation))
	binary.LittleEndian.PutUint32(buf[36:40], uint32(r.DirFD))
	binary.LittleEndian.PutUint64(buf[40:48], r.OpenFlags)
	binary.LittleEndian.PutUint64(buf[48:56], r.OpenMode)
	binary.LittleEndian.PutUint64(buf[56:64], r.ResolveFlags)
	binary.LittleEndian.PutUint32(buf[64:68], r.LookupFlags)
	binary.LittleEndian.PutUint32(buf[68:72], r.StatMask)
	binary.LittleEndian.PutUint32(buf[72:76], r.AccessMode)
	binary.LittleEndian.PutUint32(buf[76:80], r.AccessFlags)
	binary.LittleEndian.PutUint64(buf[80:88], r.ReadlinkLen)
	binary.LittleEndian.PutUint32(buf[88:92], uint32(len(r.Path)))
	binary.LittleEndian.PutUint32(buf[92:96], uint32(len(r.ExpectedLabel)))
	copy(buf[requestHeaderSize:], r.Path)
	copy(buf[requestHeaderSize+len(r.Path):], r.ExpectedLabel)
	return buf, nil
}

func DecodeRequest(buf []byte) (Request, error) {
	if len(buf) < requestHeaderSize || len(buf) > MaxPacketBytes || binary.LittleEndian.Uint32(buf[0:4]) != requestMagic || binary.LittleEndian.Uint16(buf[4:6]) != ProtocolVersion || binary.LittleEndian.Uint16(buf[6:8]) != requestHeaderSize {
		return Request{}, errors.New("invalid file lookup request header")
	}
	pathLen := int(binary.LittleEndian.Uint32(buf[88:92]))
	labelLen := int(binary.LittleEndian.Uint32(buf[92:96]))
	if pathLen <= 0 || pathLen > MaxPathBytes || labelLen < 0 || labelLen > MaxLabelBytes || requestHeaderSize+pathLen+labelLen != len(buf) {
		return Request{}, errors.New("invalid file lookup request lengths")
	}
	r := Request{
		ID:            binary.LittleEndian.Uint64(buf[8:16]),
		HostTID:       binary.LittleEndian.Uint32(buf[16:20]),
		NamespaceTID:  binary.LittleEndian.Uint32(buf[20:24]),
		StartTime:     binary.LittleEndian.Uint64(buf[24:32]),
		Operation:     Operation(binary.LittleEndian.Uint16(buf[32:34])),
		DirFD:         int32(binary.LittleEndian.Uint32(buf[36:40])),
		OpenFlags:     binary.LittleEndian.Uint64(buf[40:48]),
		OpenMode:      binary.LittleEndian.Uint64(buf[48:56]),
		ResolveFlags:  binary.LittleEndian.Uint64(buf[56:64]),
		LookupFlags:   binary.LittleEndian.Uint32(buf[64:68]),
		StatMask:      binary.LittleEndian.Uint32(buf[68:72]),
		AccessMode:    binary.LittleEndian.Uint32(buf[72:76]),
		AccessFlags:   binary.LittleEndian.Uint32(buf[76:80]),
		ReadlinkLen:   binary.LittleEndian.Uint64(buf[80:88]),
		Path:          string(buf[requestHeaderSize : requestHeaderSize+pathLen]),
		ExpectedLabel: string(buf[requestHeaderSize+pathLen:]),
	}
	if r.ID == 0 || r.HostTID == 0 || r.NamespaceTID == 0 || r.StartTime == 0 || r.Operation <= OperationInvalid || r.Operation > OperationReadlinkMetadata {
		return Request{}, errors.New("invalid file lookup request fields")
	}
	return r, nil
}

type Result struct {
	ID     uint64
	Class  Class
	Reason Reason
	Errno  int32
}

func EncodeResult(r Result) ([]byte, error) {
	if r.ID == 0 || r.Class > ClassStale || r.Reason > ReasonErrno || r.Errno < 0 {
		return nil, errors.New("invalid file lookup result")
	}
	buf := make([]byte, resultSize)
	binary.LittleEndian.PutUint32(buf[0:4], resultMagic)
	binary.LittleEndian.PutUint16(buf[4:6], ProtocolVersion)
	binary.LittleEndian.PutUint16(buf[6:8], uint16(resultSize))
	binary.LittleEndian.PutUint64(buf[8:16], r.ID)
	binary.LittleEndian.PutUint16(buf[16:18], uint16(r.Class))
	binary.LittleEndian.PutUint16(buf[18:20], uint16(r.Reason))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(r.Errno))
	return buf, nil
}

func DecodeResult(buf []byte) (Result, error) {
	if len(buf) != resultSize || binary.LittleEndian.Uint32(buf[0:4]) != resultMagic || binary.LittleEndian.Uint16(buf[4:6]) != ProtocolVersion || binary.LittleEndian.Uint16(buf[6:8]) != resultSize {
		return Result{}, errors.New("invalid file lookup result header")
	}
	r := Result{
		ID:     binary.LittleEndian.Uint64(buf[8:16]),
		Class:  Class(binary.LittleEndian.Uint16(buf[16:18])),
		Reason: Reason(binary.LittleEndian.Uint16(buf[18:20])),
		Errno:  int32(binary.LittleEndian.Uint32(buf[20:24])),
	}
	if r.ID == 0 || r.Class > ClassStale || r.Reason > ReasonErrno || r.Errno < 0 {
		return Result{}, fmt.Errorf("invalid file lookup result fields")
	}
	return r, nil
}

func HelloPacketSize() int  { return helloSize }
func ResultPacketSize() int { return resultSize }
