//go:build !linux

package externalrunner

import (
	"context"
	"fmt"
)

func (p *Provider) recoverV2(context.Context, string, string, string) (*providerInstance, error) {
	return nil, fmt.Errorf("external v2 recovery is supported only on Linux")
}
