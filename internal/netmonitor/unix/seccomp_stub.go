//go:build !linux || !cgo

package unix

import "fmt"

func DetectSupport() error { return fmt.Errorf("seccomp not supported on this platform") }
