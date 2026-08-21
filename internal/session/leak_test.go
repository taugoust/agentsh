package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/testutil/leakcheck"
)

func TestMain(m *testing.M) {
	leakcheck.VerifyTestMain(m)
}
