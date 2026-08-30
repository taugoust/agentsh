//go:build !linux

package externalrunner

import "os"

func operatorPolicyOwnerTrusted(os.FileInfo) bool { return true }
