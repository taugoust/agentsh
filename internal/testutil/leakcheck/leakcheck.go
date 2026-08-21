package leakcheck

import (
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// VerifyTestMain runs a package test suite and, when AGENTSH_LEAKCHECK=1,
// fails it if the suite leaves goroutines or platform resources behind.
// Resource snapshots are retried to allow asynchronous close and process-
// reaping paths to finish.
func VerifyTestMain(m *testing.M) {
	if os.Getenv("AGENTSH_LEAKCHECK") != "1" {
		os.Exit(m.Run())
	}
	if err := prepareResourceTracking(); err != nil {
		fmt.Fprintf(os.Stderr, "leakcheck: prepare resource tracking: %v\n", err)
		os.Exit(1)
	}
	baseline, err := snapshotResources()
	if err != nil {
		fmt.Fprintf(os.Stderr, "leakcheck: capture baseline: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	if code == 0 {
		if err := goleak.Find(); err != nil {
			fmt.Fprintf(os.Stderr, "leakcheck: goroutine leak: %v\n", err)
			code = 1
		}
	}
	if code == 0 {
		if leaked, err := waitForResourceCleanup(baseline, 2*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "leakcheck: inspect resources: %v\n", err)
			code = 1
		} else if len(leaked) != 0 {
			fmt.Fprintf(os.Stderr, "leakcheck: resources left open:\n")
			for _, resource := range leaked {
				fmt.Fprintf(os.Stderr, "  %s\n", resource)
			}
			code = 1
		}
	}
	os.Exit(code)
}

func waitForResourceCleanup(baseline resourceSnapshot, timeout time.Duration) ([]string, error) {
	deadline := time.Now().Add(timeout)
	for {
		current, err := snapshotResources()
		if err != nil {
			return nil, err
		}
		leaked := diffResources(baseline, current)
		if len(leaked) == 0 {
			return nil, nil
		}
		if time.Now().After(deadline) {
			sort.Strings(leaked)
			return leaked, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}
