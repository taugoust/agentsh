//go:build !linux

package nethelper

import "fmt"

func ValidatePrivilegedServiceUser() error {
	return fmt.Errorf("the privileged nethelper service is supported only on linux")
}
