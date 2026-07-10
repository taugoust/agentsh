//go:build linux

package nethelper

import "testing"

func TestUIDMapLeavesHostRootUnmapped(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "initial namespace", data: "0 0 4294967295\n", want: false},
		{name: "systemd private tmp namespace", data: "1000 1000 1\n", want: true},
		{name: "multiple non-root ranges", data: "0 1000 1\n1 100000 65536\n", want: true},
		{name: "host root mapped at another namespace uid", data: "1000 0 1\n", want: false},
		{name: "empty", data: "", want: false},
		{name: "malformed", data: "1000 nope 1\n", want: false},
		{name: "zero size", data: "1000 1000 0\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uidMapLeavesHostRootUnmapped([]byte(tt.data)); got != tt.want {
				t.Fatalf("uidMapLeavesHostRootUnmapped() = %t, want %t", got, tt.want)
			}
		})
	}
}
