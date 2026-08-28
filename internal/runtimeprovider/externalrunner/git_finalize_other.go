//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
)

func FinalizeGitDraftStorage(context.Context, string, string, string) (GitTerminalRecord, error) {
	return GitTerminalRecord{}, fmt.Errorf("external Git Draft storage finalization is supported only on Linux")
}
