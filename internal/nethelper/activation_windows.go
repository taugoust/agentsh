//go:build windows

package nethelper

import "net"

func ListenSystemdActivation(string) (net.Listener, bool, error) {
	return nil, false, nil
}

func ListenSystemdActivationForUID(string, uint32) (net.Listener, bool, error) {
	return nil, false, nil
}
