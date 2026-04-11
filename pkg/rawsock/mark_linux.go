//go:build linux

package rawsock

import (
	"fmt"
	"syscall"
)

// SetMark marks all packets emitted from this raw socket.
func (s *platformRawSocket) SetMark(mark uint32) error {
	if err := syscall.SetsockoptInt(s.fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
		return fmt.Errorf("SO_MARK: %w", err)
	}
	return nil
}
