package cli

import "testing"

func TestGuestControlCommandExposesFixedInputs(t *testing.T) {
	root := newGuestControlCmd("test")
	if !root.Hidden {
		t.Fatal("guest control command must remain hidden from ordinary users")
	}
	run, _, err := root.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"manifest", "handshake", "workspace", "volume-root", "profile", "profile-digest",
		"allowed-policy", "probe-command", "probe-arg",
	} {
		if run.Flags().Lookup(name) == nil {
			t.Fatalf("guest control run is missing --%s", name)
		}
	}
}

func TestGuestControlRequestAdmissionIsBoundedAndRejectsReplay(t *testing.T) {
	handler := &guestControlHandler{}
	if !handler.ClaimRequest("request-0") || handler.ClaimRequest("request-0") {
		t.Fatal("guest control did not reject a replayed request identity")
	}
	for index := 1; index < 4096; index++ {
		if !handler.ClaimRequest(requestID(index)) {
			t.Fatalf("request %d was refused before the admission bound", index)
		}
	}
	if handler.ClaimRequest("request-overflow") {
		t.Fatal("guest control accepted a request beyond its admission bound")
	}
}

func requestID(index int) string {
	const digits = "0123456789"
	if index == 0 {
		return "request-0"
	}
	var reversed [20]byte
	position := len(reversed)
	for index > 0 {
		position--
		reversed[position] = digits[index%10]
		index /= 10
	}
	return "request-" + string(reversed[position:])
}
