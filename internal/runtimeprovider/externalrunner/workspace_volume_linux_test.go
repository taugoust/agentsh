//go:build linux

package externalrunner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	testWorkspaceVolumeID         = "22222222-2222-4222-8222-222222222222"
	testOtherWorkspaceVolumeID    = "33333333-3333-4333-8333-333333333333"
	testWorkspaceVolumeSessionID  = "session-11111111-1111-4111-8111-111111111111"
	testQcow2StructuralMarker     = "agentsh-test-qcow2-structure"
	packagedQEMUImgIntegrationEnv = "AGENTSH_TEST_PACKAGED_QEMU_IMG"
)

func testWorkspaceVolumeRequest(t *testing.T) WorkspaceVolumeRequest {
	t.Helper()
	profile := testProfile(t)
	profile.Schema = ProfileSchemaV2
	profile.Name = "pi-linux-qemu-v2"
	profile.WorkspaceVolume = &WorkspaceVolumeSpec{
		Model:            WorkspaceVolumeModel,
		Format:           WorkspaceVolumeFormat,
		Filesystem:       WorkspaceVolumeFilesystem,
		RunnerFD:         WorkspaceVolumeRunnerFD,
		VirtualSizeBytes: 8 << 30,
	}
	stateDir := filepath.Join(t.TempDir(), testWorkspaceVolumeSessionID)
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return WorkspaceVolumeRequest{
		StateDir: stateDir, SessionID: testWorkspaceVolumeSessionID, Profile: profile,
		ProfileFileSHA256: digest([]byte("operator-profile-file")),
	}
}

func testWorkspaceVolumeDependencies(t *testing.T, inspect func(string, string, *os.File, ...string) error) workspaceVolumeDependencies {
	t.Helper()
	return workspaceVolumeDependencies{
		resolveQEMUImg: func(name string) (string, error) {
			if name != "qemu-img" {
				t.Fatalf("resolved executable = %q", name)
			}
			return filepath.Join(string(filepath.Separator), "packaged", "bin", "qemu-img"), nil
		},
		runQEMUImg: func(ctx context.Context, executable, workingDirectory string, image *os.File, args ...string) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if inspect != nil {
				if err := inspect(executable, workingDirectory, image, args...); err != nil {
					return nil, err
				}
			}
			if len(args) == 0 {
				return nil, errors.New("missing qemu-img operation")
			}
			switch args[0] {
			case "create":
				if image != nil || len(args) != 8 {
					return nil, fmt.Errorf("qemu-img create args = %#v, image = %v", args, image)
				}
				size, err := strconv.ParseInt(args[7], 10, 64)
				if err != nil {
					return nil, err
				}
				return nil, writeTestQcow2(args[6], size, 0o644)
			case "info", "check", "map":
				if image == nil || len(args) != 5 || args[1] != "--output=json" || args[2] != "-f" || args[3] != WorkspaceVolumeFormat {
					return nil, fmt.Errorf("qemu-img validation args = %#v, image = %v", args, image)
				}
				wantDescriptor := filepath.Join(string(filepath.Separator), "proc", "self", "fd", "3")
				if args[4] != wantDescriptor {
					return nil, fmt.Errorf("qemu-img descriptor = %q, want %q", args[4], wantDescriptor)
				}
				virtualSize, err := validateTestQcow2(image)
				if err != nil {
					return nil, err
				}
				switch args[0] {
				case "info":
					return []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1","corrupt":false}}}`, virtualSize)), nil
				case "check":
					return []byte(`{"format":"qcow2","check-errors":0}`), nil
				default:
					return []byte(fmt.Sprintf(`[{"start":0,"length":%d,"depth":0,"present":false,"zero":true,"data":false}]`, virtualSize)), nil
				}
			default:
				return nil, fmt.Errorf("unexpected qemu-img operation %q", args[0])
			}
		},
		now: func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	}
}

func writeTestQcow2(path string, virtualSize int64, mode os.FileMode) error {
	header := make([]byte, qcow2ValidationHeaderBytes)
	binary.BigEndian.PutUint32(header[0:4], 0x514649fb)
	binary.BigEndian.PutUint32(header[4:8], 3)
	binary.BigEndian.PutUint32(header[20:24], 16)
	binary.BigEndian.PutUint64(header[24:32], uint64(virtualSize))
	binary.BigEndian.PutUint32(header[100:104], qcow2ValidationHeaderBytes)
	data := append(header, []byte(testQcow2StructuralMarker)...)
	return os.WriteFile(path, data, mode)
}

func validateTestQcow2(image *os.File) (int64, error) {
	data := make([]byte, qcow2ValidationHeaderBytes+len(testQcow2StructuralMarker))
	if _, err := image.ReadAt(data, 0); err != nil {
		return 0, fmt.Errorf("synthetic qemu-img detected truncated image: %w", err)
	}
	if string(data[qcow2ValidationHeaderBytes:]) != testQcow2StructuralMarker {
		return 0, errors.New("synthetic qemu-img detected invalid in-place replacement")
	}
	return int64(binary.BigEndian.Uint64(data[24:32])), nil
}

func TestWorkspaceVolumeCreatePublishesAndReopensExactImage(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	var operations []string
	deps := testWorkspaceVolumeDependencies(t, func(executable, workingDirectory string, image *os.File, args ...string) error {
		operations = append(operations, args[0])
		if executable != filepath.Join(string(filepath.Separator), "packaged", "bin", "qemu-img") {
			t.Fatalf("qemu-img executable = %q", executable)
		}
		if args[0] == "create" {
			if filepath.Dir(args[6]) != workingDirectory || args[2] != "-f" || args[3] != WorkspaceVolumeFormat || args[4] != "-o" || args[5] != "compat=1.1" {
				t.Fatalf("qemu-img invocation = %#v in %q", args, workingDirectory)
			}
			joined := strings.Join(args, " ")
			for _, forbidden := range []string{"mount", "loop", "nbd", filepath.Join(request.StateDir, "runtime", "workspace")} {
				if strings.Contains(joined, forbidden) {
					t.Fatalf("qemu-img invocation contains forbidden staging or attachment term %q: %s", forbidden, joined)
				}
			}
		} else if image == nil {
			t.Fatal("qemu-img validation did not receive the exact read-only image")
		}
		return nil
	})

	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if volume.RunnerFD() != WorkspaceVolumeRunnerFD {
		t.Fatalf("runner FD = %d", volume.RunnerFD())
	}
	if strings.Join(operations, ",") != "create,info,check,map,info,check,map" {
		t.Fatalf("qemu-img operations = %v", operations)
	}
	manifest := volume.Manifest
	if manifest.SessionID != request.SessionID || manifest.Provider != ProviderName || manifest.Profile != request.Profile.Name ||
		manifest.ProfileFileSHA256 != request.ProfileFileSHA256 || manifest.VolumeID != testWorkspaceVolumeID || manifest.Image.Inode == 0 {
		t.Fatalf("manifest = %#v", manifest)
	}
	layout := workspaceVolumePaths(request.StateDir)
	for path, mode := range map[string]os.FileMode{
		layout.workspaceDir: 0o700,
		layout.manifestPath: 0o600,
		layout.imagePath:    0o600,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s mode = %v, err = %v", path, info, err)
		}
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(layout.workspaceDir); err != nil {
		t.Fatalf("Close deleted published volume: %v", err)
	}

	reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), request, manifest.VolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Manifest != manifest {
		t.Fatalf("reopened manifest = %#v, want %#v", reopened.Manifest, manifest)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceVolumeCreateIsCallerIdentifiedAndIdempotent(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	var creates int
	deps := testWorkspaceVolumeDependencies(t, func(_ string, _ string, _ *os.File, args ...string) error {
		if args[0] == "create" {
			creates++
		}
		return nil
	})
	first, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	want := first.Manifest
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if second.Manifest != want || creates != 1 {
		t.Fatalf("idempotent create manifest = %#v, creates = %d", second.Manifest, creates)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testOtherWorkspaceVolumeID, deps); !errors.Is(err, ErrWorkspaceVolumeExists) {
		if volume != nil {
			_ = volume.Close()
		}
		t.Fatalf("different caller volume ID error = %v", err)
	}
}

func TestWorkspaceVolumeCreateRecoversOnlyExactTransaction(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	layout := workspaceVolumePaths(request.StateDir)
	if err := prepareWorkspaceVolumeLayout(layout, true); err != nil {
		t.Fatal(err)
	}
	transactionDir := workspaceVolumeCreateTransactionPath(layout, testWorkspaceVolumeID)
	prepareDir, err := os.MkdirTemp(layout.volumesDir, workspaceVolumePreparePrefix+testWorkspaceVolumeID+"-")
	if err != nil {
		t.Fatal(err)
	}
	intent := newWorkspaceVolumeCreateIntent(request, testWorkspaceVolumeID, deps.now())
	if err := writeWorkspaceVolumeCreateIntent(filepath.Join(prepareDir, workspaceVolumeCreateIntentName), intent); err != nil {
		t.Fatal(err)
	}

	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(transactionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered create transaction survived publication: %v", err)
	}
	if _, err := os.Lstat(prepareDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovered preparation survived publication: %v", err)
	}

	other := testWorkspaceVolumeRequest(t)
	otherLayout := workspaceVolumePaths(other.StateDir)
	if err := prepareWorkspaceVolumeLayout(otherLayout, true); err != nil {
		t.Fatal(err)
	}
	otherTransaction := workspaceVolumeCreateTransactionPath(otherLayout, testWorkspaceVolumeID)
	if err := os.Mkdir(otherTransaction, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := newWorkspaceVolumeCreateIntent(other, testWorkspaceVolumeID, deps.now())
	foreign.ProfileFileSHA256 = digest([]byte("foreign-profile"))
	if err := writeWorkspaceVolumeCreateIntent(filepath.Join(otherTransaction, workspaceVolumeCreateIntentName), foreign); err != nil {
		t.Fatal(err)
	}
	if got, err := createWorkspaceVolumeWithDependencies(context.Background(), other, testWorkspaceVolumeID, deps); !errors.Is(err, ErrWorkspaceVolumeExists) || !errors.Is(err, ErrWorkspaceVolumeInvalid) {
		if got != nil {
			_ = got.Close()
		}
		t.Fatalf("foreign create transaction error = %v", err)
	}
	if _, err := os.Lstat(otherTransaction); err != nil {
		t.Fatalf("foreign create transaction was altered: %v", err)
	}
}

func TestWorkspaceVolumeReopenRejectsReplacementTruncationAndProfileConfusion(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	manifest := volume.Manifest
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}

	confused := request
	confused.ProfileFileSHA256 = digest([]byte("different-profile-file"))
	if reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), confused, manifest.VolumeID, deps); !errors.Is(err, ErrWorkspaceVolumeInvalid) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("cross-profile reopen error = %v", err)
	}

	layout := workspaceVolumePaths(request.StateDir)
	replacement := filepath.Join(layout.workspaceDir, "replacement.qcow2")
	if err := writeTestQcow2(replacement, request.Profile.WorkspaceVolume.VirtualSizeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, layout.imagePath); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), request, manifest.VolumeID, deps); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("replacement reopen error = %v", err)
	}

	truncatedRequest := testWorkspaceVolumeRequest(t)
	truncated, err := createWorkspaceVolumeWithDependencies(context.Background(), truncatedRequest, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := truncated.Close(); err != nil {
		t.Fatal(err)
	}
	truncatedLayout := workspaceVolumePaths(truncatedRequest.StateDir)
	if err := os.Truncate(truncatedLayout.imagePath, qcow2ValidationHeaderBytes); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), truncatedRequest, testWorkspaceVolumeID, deps); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("in-place truncation reopen error = %v", err)
	}
}

func TestWorkspaceVolumeMutableLeaseIsExclusive(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if second, err := openWorkspaceVolumeWithDependencies(ctx, request, testWorkspaceVolumeID, deps); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second mutable holder error = %v, want deadline", err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceVolumeDeleteIsExplicitIdempotentAndLeaseGuarded(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	volumeID := volume.Manifest.VolumeID
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := deleteWorkspaceVolumeWithDependencies(ctx, request, volumeID, deps); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Delete while open error = %v, want deadline", err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	if err := deleteWorkspaceVolumeWithDependencies(context.Background(), request, volumeID, deps); err != nil {
		t.Fatal(err)
	}
	if err := deleteWorkspaceVolumeWithDependencies(context.Background(), request, volumeID, deps); err != nil {
		t.Fatalf("repeated Delete: %v", err)
	}
	layout := workspaceVolumePaths(request.StateDir)
	if _, err := os.Lstat(layout.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workspace survived explicit deletion: %v", err)
	}
	if _, err := os.Lstat(workspaceVolumeTombstonePath(layout, volumeID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deletion tombstone survived: %v", err)
	}
}

func TestWorkspaceVolumeFailedCreatePublishesNothingAndCanResume(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	goodRunner := deps.runQEMUImg
	deps.runQEMUImg = func(ctx context.Context, executable, workingDirectory string, image *os.File, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "create" {
			size, err := strconv.ParseInt(args[7], 10, 64)
			if err != nil {
				return nil, err
			}
			if err := writeTestQcow2(args[6], size, 0o644); err != nil {
				return nil, err
			}
			return nil, errors.New("injected qemu-img failure")
		}
		return goodRunner(ctx, executable, workingDirectory, image, args...)
	}
	if volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps); err == nil {
		if volume != nil {
			_ = volume.Close()
		}
		t.Fatal("failed qemu-img create succeeded")
	}
	layout := workspaceVolumePaths(request.StateDir)
	if _, err := os.Lstat(layout.workspaceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed create published workspace: %v", err)
	}
	transactionDir := workspaceVolumeCreateTransactionPath(layout, testWorkspaceVolumeID)
	if _, err := os.Lstat(filepath.Join(transactionDir, workspaceVolumeCreateIntentName)); err != nil {
		t.Fatalf("failed exact transaction is not recoverable: %v", err)
	}

	deps.runQEMUImg = goodRunner
	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(transactionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resumed transaction survived publication: %v", err)
	}
}

func TestWorkspaceVolumeManifestIsStrictAndPrivate(t *testing.T) {
	request := testWorkspaceVolumeRequest(t)
	deps := testWorkspaceVolumeDependencies(t, nil)
	volume, err := createWorkspaceVolumeWithDependencies(context.Background(), request, testWorkspaceVolumeID, deps)
	if err != nil {
		t.Fatal(err)
	}
	volumeID := volume.Manifest.VolumeID
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	layout := workspaceVolumePaths(request.StateDir)
	data, err := os.ReadFile(layout.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("{}\n")...)
	if err := os.WriteFile(layout.manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := openWorkspaceVolumeWithDependencies(context.Background(), request, volumeID, deps); !errors.Is(err, ErrWorkspaceVolumeInvalid) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("non-strict manifest reopen error = %v", err)
	}
}

func TestWorkspaceVolumeQEMUJSONValidation(t *testing.T) {
	const size = int64(8 << 30)
	if err := validateWorkspaceVolumeQEMUInfoJSON(make([]byte, maxQEMUImgJSONBytes+1), size); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		t.Fatalf("oversized qemu-img JSON error = %v", err)
	}
	bounded := boundedQEMUImgOutput{limit: 4}
	if written, err := bounded.Write([]byte("123456")); err != nil || written != 6 || string(bounded.data) != "1234" || !bounded.truncated {
		t.Fatalf("bounded qemu-img output = %q, %d, %v, truncated=%t", bounded.data, written, err, bounded.truncated)
	}
	validInfo := []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1","corrupt":false}}}`, size))
	if err := validateWorkspaceVolumeQEMUInfoJSON(validInfo, size); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"old compatibility": []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"0.10"}}}`, size)),
		"wrong size":        []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1"}}}`, size+1)),
		"backing file":      []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","backing-filename":"base.qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1"}}}`, size)),
		"data file":         []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1","data-file":"data.raw"}}}`, size)),
		"corrupt":           []byte(fmt.Sprintf(`{"virtual-size":%d,"format":"qcow2","format-specific":{"type":"qcow2","data":{"compat":"1.1","corrupt":true}}}`, size)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateWorkspaceVolumeQEMUInfoJSON(data, size); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
	if err := validateWorkspaceVolumeQEMUCheckJSON([]byte(`{"format":"qcow2","check-errors":0}`), true); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceVolumeQEMUCheckJSON([]byte(`{"format":"qcow2","check-errors":1,"corruptions":1}`), false); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		t.Fatalf("check error = %v", err)
	}
	if err := validateWorkspaceVolumeQEMUCheckJSON([]byte(`{"format":"qcow2","check-errors":0,"allocated-clusters":1}`), true); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		t.Fatalf("allocated initial image check error = %v", err)
	}
	blankMap := []byte(fmt.Sprintf(`[{"start":0,"length":%d,"depth":0,"present":false,"zero":true,"data":false}]`, size))
	if err := validateWorkspaceVolumeQEMUMapJSON(blankMap, size, true); err != nil {
		t.Fatal(err)
	}
	mutableMap := []byte(fmt.Sprintf(`[{"start":0,"length":4096,"depth":0,"present":true,"zero":false,"data":true},{"start":4096,"length":%d,"depth":0,"present":false,"zero":true,"data":false}]`, size-4096))
	if err := validateWorkspaceVolumeQEMUMapJSON(mutableMap, size, false); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkspaceVolumeQEMUMapJSON(mutableMap, size, true); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		t.Fatalf("nonblank initial map error = %v", err)
	}
	if err := validateWorkspaceVolumeQEMUMapJSON([]byte(`[]`), size, false); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		t.Fatalf("incomplete map error = %v", err)
	}
}

func TestWorkspaceVolumePackagedQEMUImgIntegration(t *testing.T) {
	if os.Getenv(packagedQEMUImgIntegrationEnv) != "1" {
		t.Skip("packaged qemu-img integration is exercised by the focused Nix check")
	}
	if path := os.Getenv("PATH"); path != "" {
		t.Fatalf("ambient PATH = %q, want empty", path)
	}
	if os.Geteuid() == 0 {
		t.Fatal("focused packaged qemu-img check must run unprivileged")
	}
	request := testWorkspaceVolumeRequest(t)
	stateInfo, err := os.Lstat(request.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	stateStat, ok := stateInfo.Sys().(*syscall.Stat_t)
	if !ok || stateStat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("state tree owner = %#v, euid = %d", stateInfo.Sys(), os.Geteuid())
	}

	volume, err := CreateWorkspaceVolume(context.Background(), request, testWorkspaceVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	manifest := volume.Manifest
	if err := volume.Close(); err != nil {
		t.Fatal(err)
	}
	idempotent, err := CreateWorkspaceVolume(context.Background(), request, testWorkspaceVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent.Manifest != manifest {
		t.Fatalf("idempotent packaged create manifest = %#v, want %#v", idempotent.Manifest, manifest)
	}
	if err := idempotent.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWorkspaceVolume(context.Background(), request, testWorkspaceVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := DeleteWorkspaceVolume(context.Background(), request, testWorkspaceVolumeID); err != nil {
		t.Fatal(err)
	}

	truncatedRequest := testWorkspaceVolumeRequest(t)
	truncated, err := CreateWorkspaceVolume(context.Background(), truncatedRequest, testWorkspaceVolumeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := truncated.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(workspaceVolumePaths(truncatedRequest.StateDir).imagePath, qcow2ValidationHeaderBytes); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenWorkspaceVolume(context.Background(), truncatedRequest, testWorkspaceVolumeID); !errors.Is(err, ErrWorkspaceVolumeCorrupt) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("packaged qemu-img truncation error = %v", err)
	}
}
