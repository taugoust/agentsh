//go:build linux

package externalrunner

import (
	"io/fs"
	"syscall"
	"testing"
	"time"
)

type policyOwnerFileInfo struct{ uid uint32 }

func (policyOwnerFileInfo) Name() string       { return "policy.yaml" }
func (policyOwnerFileInfo) Size() int64        { return 1 }
func (policyOwnerFileInfo) Mode() fs.FileMode  { return 0o444 }
func (policyOwnerFileInfo) ModTime() time.Time { return time.Time{} }
func (policyOwnerFileInfo) IsDir() bool        { return false }
func (i policyOwnerFileInfo) Sys() any         { return &syscall.Stat_t{Uid: i.uid} }

func TestOperatorPolicyOverflowOwnerOnlyTrustedInNixStore(t *testing.T) {
	info := policyOwnerFileInfo{uid: linuxOverflowUID}
	if !operatorPolicyOwnerTrusted("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-policy/policy.yaml", info) {
		t.Fatal("overflow-mapped root-owned Nix store policy was rejected")
	}
	if operatorPolicyOwnerTrusted("/tmp/policy.yaml", info) {
		t.Fatal("overflow-owned policy outside the Nix store was trusted")
	}
}
