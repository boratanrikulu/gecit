//go:build windows && !cgo

package capture

func tryPcapCapture(iface string, ports []uint16) (Detector, error, bool) {
	return nil, nil, false
}
