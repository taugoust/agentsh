//go:build !linux || !cgo

package unix

import (
	"errors"
	"os"
	"time"
)

type FileLookupBrokerConfig struct {
	Endpoint           *os.File
	ExpectedWrapperPID int
	ExpectedPayloadPID int
	Timeout            time.Duration
}

func NewFileLookupBroker(cfg FileLookupBrokerConfig) (FileLookupBroker, error) {
	if cfg.Endpoint != nil {
		_ = cfg.Endpoint.Close()
	}
	return nil, errors.New("tracee-lineage file lookup broker is unavailable on this platform")
}
