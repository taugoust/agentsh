//go:build !linux

package nethelper

import "fmt"

type processIdentity struct {
	pid       int
	startTime uint64
}

func openProcessIdentity(int) (*processIdentity, error) {
	return nil, fmt.Errorf("stable helper peer process identity is only available on linux")
}

func (p *processIdentity) clone() (*processIdentity, error) {
	return nil, fmt.Errorf("stable helper peer process identity is only available on linux")
}

func (p *processIdentity) validate() error {
	return fmt.Errorf("stable helper peer process identity is only available on linux")
}

func (p *processIdentity) alive() bool { return false }
func (p *processIdentity) close()      {}
