//go:build !linux

package nethelper

import "fmt"

type unavailableCgroupResolver struct{}

func defaultCgroupResolver() CgroupResolver { return unavailableCgroupResolver{} }

func (unavailableCgroupResolver) CgroupPathForPID(int) (string, error) {
	return "", fmt.Errorf("kernel cgroup authorization is only available on linux")
}
func (unavailableCgroupResolver) CanonicalCgroupPath(string) (string, error) {
	return "", fmt.Errorf("kernel cgroup authorization is only available on linux")
}
func (unavailableCgroupResolver) SameCgroupPath(string, string) (bool, error) {
	return false, fmt.Errorf("kernel cgroup authorization is only available on linux")
}
func (unavailableCgroupResolver) CgroupPathContains(string, string) (bool, error) {
	return false, fmt.Errorf("kernel cgroup authorization is only available on linux")
}
