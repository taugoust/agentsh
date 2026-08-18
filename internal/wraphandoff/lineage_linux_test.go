//go:build linux

package wraphandoff

import (
	"os"
	"testing"
)

func TestLineageHandoffTwoPhaseRoundTrip(t *testing.T) {
	client, server := socketPairConns(t)
	if err := SendPrelude(client, Metadata{WrapperPID: 41, CommandJail: true}); err != nil {
		t.Fatal(err)
	}
	prelude, err := RecvPrelude(server)
	if err != nil {
		t.Fatal(err)
	}
	if prelude.WrapperPID != 41 || !prelude.CommandJail || prelude.PayloadPID != 0 {
		t.Fatalf("prelude = %+v", prelude)
	}

	notifyR, notifyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	lookupR, lookupW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	setupR, setupW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer notifyR.Close()
	defer notifyW.Close()
	defer lookupR.Close()
	defer lookupW.Close()
	defer setupR.Close()
	defer setupW.Close()

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- SendPayloadHandoff(client, int(notifyR.Fd()), int(setupR.Fd()), int(lookupR.Fd()), Metadata{
			WrapperPID: 41, PayloadPID: 42, CommandJail: true,
		})
	}()
	handoff, err := RecvHandoff(server)
	if err != nil {
		t.Fatal(err)
	}
	defer handoff.Close()
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if !handoff.HasMetadata || handoff.Metadata.WrapperPID != 41 || handoff.Metadata.PayloadPID != 42 || !handoff.Metadata.FileLookupBroker || !handoff.Metadata.CompositionSetup {
		t.Fatalf("metadata = %+v", handoff.Metadata)
	}
	if handoff.NotifyFD == nil || handoff.FileLookupBroker == nil || handoff.CompositionSetup == nil {
		t.Fatalf("incomplete handoff: %+v", handoff)
	}
}
