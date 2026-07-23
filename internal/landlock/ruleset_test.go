//go:build linux

package landlock

import (
	"testing"
)

func TestRulesetBuilder_AddPath(t *testing.T) {
	b := NewRulesetBuilder(3) // ABI v3

	err := b.AddExecutePath("/usr/bin")
	if err != nil {
		t.Errorf("failed to add execute path: %v", err)
	}

	err = b.AddReadPath("/etc/ssl/certs")
	if err != nil {
		t.Errorf("failed to add read path: %v", err)
	}

	err = b.AddListPath("/")
	if err != nil {
		t.Errorf("failed to add list path: %v", err)
	}

	if len(b.executePaths) != 1 {
		t.Errorf("expected 1 execute path, got %d", len(b.executePaths))
	}
	if len(b.readPaths) != 1 {
		t.Errorf("expected 1 read path, got %d", len(b.readPaths))
	}
	if len(b.listPaths) != 1 || b.listPaths[0] != "/" {
		t.Errorf("expected exact root list path, got %#v", b.listPaths)
	}
}

func TestRulesetBuilder_DenyPaths(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.AddDenyPath("/var/run/docker.sock")

	if len(b.denyPaths) != 1 {
		t.Errorf("expected 1 deny path, got %d", len(b.denyPaths))
	}
}

func TestRulesetBuilder_WorkspacePath(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.SetWorkspace("/home/user/project")

	if b.workspace != "/home/user/project" {
		t.Errorf("expected workspace /home/user/project, got %s", b.workspace)
	}
}

func TestRulesetBuilder_NetworkAccess(t *testing.T) {
	b := NewRulesetBuilder(4) // ABI v4 for network support
	b.SetNetworkAccess(true, false)

	if !b.allowNetwork {
		t.Error("expected allowNetwork to be true")
	}
	if b.allowBind {
		t.Error("expected allowBind to be false")
	}
}

func TestRulesetBuilder_DeviceIOCTLIsCompositionOptIn(t *testing.T) {
	ordinary := NewRulesetBuilder(7)
	if mask := ordinary.buildFSAccessMask(); mask&LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 {
		t.Fatal("ordinary ruleset unexpectedly handles IOCTL_DEV")
	}

	composition := NewRulesetBuilder(7)
	composition.SetDeviceIOCTLPolicy(true)
	if mask := composition.buildFSAccessMask(); mask&LANDLOCK_ACCESS_FS_IOCTL_DEV == 0 {
		t.Fatal("composition ruleset does not handle IOCTL_DEV")
	}
	if mask := composition.buildWriteAccessMask(); mask&LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 {
		t.Fatal("ordinary write authority must not imply device ioctl authority")
	}

	legacy := NewRulesetBuilder(4)
	legacy.SetDeviceIOCTLPolicy(true)
	if mask := legacy.buildFSAccessMask(); mask&LANDLOCK_ACCESS_FS_IOCTL_DEV != 0 {
		t.Fatal("IOCTL_DEV was enabled before ABI 5")
	}
}

func TestRulesetBuilder_AddDeviceIOCTLPathRequiresExactPath(t *testing.T) {
	builder := NewRulesetBuilder(7)
	if err := builder.AddDeviceIOCTLPath("/dev/null"); err != nil {
		t.Fatalf("AddDeviceIOCTLPath(/dev/null): %v", err)
	}
	if len(builder.deviceIOCTLPaths) != 1 || builder.deviceIOCTLPaths[0] != "/dev/null" {
		t.Fatalf("device ioctl paths = %#v", builder.deviceIOCTLPaths)
	}
	for _, path := range []string{"dev/null", "/dev/*", "/dev/../dev/null"} {
		if err := builder.AddDeviceIOCTLPath(path); err == nil {
			t.Errorf("AddDeviceIOCTLPath(%q) unexpectedly succeeded", path)
		}
	}
}

func TestRulesetBuilder_WriteAccessMask_IncludesCreationRights(t *testing.T) {
	// Write-allowed paths must support normal writable-directory creation rights.
	// Without MAKE_SOCK, bind() for Unix sockets in /tmp etc. fails with EACCES.
	// Without MAKE_SYM, Nix cache updates like flake-registry symlink creation
	// under $XDG_CACHE_HOME fail with EACCES.
	b := NewRulesetBuilder(3)
	mask := b.buildWriteAccessMask()

	if mask&LANDLOCK_ACCESS_FS_MAKE_SOCK == 0 {
		t.Error("writeAccessMask missing MAKE_SOCK — Unix socket creation blocked in write-allowed paths")
	}
	if mask&LANDLOCK_ACCESS_FS_MAKE_SYM == 0 {
		t.Error("writeAccessMask missing MAKE_SYM — symlink creation blocked in write-allowed paths")
	}
	// Sanity: verify other expected bits are present
	if mask&LANDLOCK_ACCESS_FS_WRITE_FILE == 0 {
		t.Error("writeAccessMask missing WRITE_FILE")
	}
	if mask&LANDLOCK_ACCESS_FS_MAKE_REG == 0 {
		t.Error("writeAccessMask missing MAKE_REG")
	}
	if mask&LANDLOCK_ACCESS_FS_MAKE_DIR == 0 {
		t.Error("writeAccessMask missing MAKE_DIR")
	}
	// TRUNCATE should be present for ABI >= 3
	if mask&LANDLOCK_ACCESS_FS_TRUNCATE == 0 {
		t.Error("writeAccessMask missing TRUNCATE for ABI v3")
	}
}

func TestStripGlobPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/bin/**", "/bin"},
		{"/usr/bin/*", "/usr/bin"},
		{"/opt/*/bin/*", "/opt"},
		{"/usr/bin", "/usr/bin"},             // no glob — unchanged
		{"/etc/ssl/certs", "/etc/ssl/certs"}, // no glob — unchanged
		{"/**", "/"},
		{"/tmp/test[0-9]", "/tmp/test"},
		{"/a?b", "/a"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := stripGlobPrefix(tt.input); got != tt.want {
				t.Errorf("stripGlobPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAddExecutePath_GlobStripped(t *testing.T) {
	b := NewRulesetBuilder(3)
	err := b.AddExecutePath("/bin/**")
	if err != nil {
		t.Fatalf("AddExecutePath failed: %v", err)
	}
	if len(b.executePaths) != 1 {
		t.Fatalf("expected 1 execute path, got %d", len(b.executePaths))
	}
	if b.executePaths[0] != "/bin" {
		t.Errorf("expected /bin, got %s", b.executePaths[0])
	}
}

func TestAddReadPath_GlobStripped(t *testing.T) {
	b := NewRulesetBuilder(3)
	err := b.AddReadPath("/usr/lib/**")
	if err != nil {
		t.Fatalf("AddReadPath failed: %v", err)
	}
	if len(b.readPaths) != 1 {
		t.Fatalf("expected 1 read path, got %d", len(b.readPaths))
	}
	if b.readPaths[0] != "/usr/lib" {
		t.Errorf("expected /usr/lib, got %s", b.readPaths[0])
	}
}

func TestAddListPath_GlobRejected(t *testing.T) {
	b := NewRulesetBuilder(3)
	if err := b.AddListPath("/scratch/**"); err == nil {
		t.Fatal("AddListPath accepted a glob that Landlock cannot preserve exactly")
	}
	if len(b.listPaths) != 0 {
		t.Fatalf("list paths = %#v, want none", b.listPaths)
	}
}

func TestAddWritePath_GlobStripped(t *testing.T) {
	b := NewRulesetBuilder(3)
	err := b.AddWritePath("/tmp/**")
	if err != nil {
		t.Fatalf("AddWritePath failed: %v", err)
	}
	if len(b.writePaths) != 1 {
		t.Fatalf("expected 1 write path, got %d", len(b.writePaths))
	}
	if b.writePaths[0] != "/tmp" {
		t.Errorf("expected /tmp, got %s", b.writePaths[0])
	}
}

func TestRulesetBuilder_IsDenied(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.AddDenyPath("/var/run/docker.sock")
	b.AddDenyPath("/run/containerd")

	tests := []struct {
		path   string
		denied bool
	}{
		{"/var/run/docker.sock", true},
		{"/run/containerd", true},
		{"/run/containerd/containerd.sock", true},
		{"/usr/bin", false},
		{"/var/run/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if b.isDenied(tt.path) != tt.denied {
				t.Errorf("isDenied(%q) = %v, want %v", tt.path, b.isDenied(tt.path), tt.denied)
			}
		})
	}
}
