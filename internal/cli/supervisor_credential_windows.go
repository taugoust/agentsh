//go:build windows

package cli

import "os"

func validateSupervisorCredentialFileOwner(os.FileInfo) error { return nil }
