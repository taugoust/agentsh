//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
)

func ExportGitDraftResult(context.Context, string, string, string) (GitResultRecord, error) {
	return GitResultRecord{}, fmt.Errorf("external Git Draft export is supported only on Linux")
}

func SealGitDraft(context.Context, string, string) (GitResultRecord, error) {
	return GitResultRecord{}, fmt.Errorf("external Git Draft sealing is supported only on Linux")
}
