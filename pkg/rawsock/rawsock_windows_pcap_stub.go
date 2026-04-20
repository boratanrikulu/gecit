//go:build windows && !cgo

package rawsock

func tryPcapRawSocket() (RawSocket, error, bool) {
	return nil, nil, false
}
