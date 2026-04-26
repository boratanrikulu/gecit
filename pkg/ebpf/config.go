//go:build linux

package ebpf

import (
	"fmt"
	"math"

	gecitbpf "github.com/boratanrikulu/gecit/pkg/ebpf/bpf"
	"github.com/cilium/ebpf"
)

func (m *Manager) pushConfig() error {
	cfg, err := m.bpfConfig(1)
	if err != nil {
		return err
	}
	key := uint32(0)
	return m.objs.ConfigMap.Update(key, cfg, ebpf.UpdateAny)
}

func (m *Manager) pushTargetPorts() error {
	val := uint8(1)
	for _, port := range m.cfg.Ports {
		if err := m.objs.TargetPorts.Update(port, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) pushExcludeIPs() error {
	val := uint8(1)
	for _, ip := range m.cfg.ExcludeIPs {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		// Network byte order — same as ctx.RemoteIp4 in BPF.
		key := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
		if err := m.objs.ExcludeIps.Update(key, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// UpdateEnabled flips the master switch at runtime without reloading BPF.
func (m *Manager) UpdateEnabled(enabled bool) error {
	e := uint8(0)
	if enabled {
		e = 1
	}
	cfg, err := m.bpfConfig(e)
	if err != nil {
		return err
	}
	key := uint32(0)
	return m.objs.ConfigMap.Update(key, cfg, ebpf.UpdateAny)
}

func (m *Manager) bpfConfig(enabled uint8) (gecitbpf.Config, error) {
	if m.cfg.MSS < 1 || m.cfg.MSS > math.MaxUint16 {
		return gecitbpf.Config{}, fmt.Errorf("MSS out of range for BPF config: %d", m.cfg.MSS)
	}
	if m.cfg.RestoreMSS < 0 || m.cfg.RestoreMSS > math.MaxUint16 {
		return gecitbpf.Config{}, fmt.Errorf("restore MSS out of range for BPF config: %d", m.cfg.RestoreMSS)
	}
	if m.cfg.RestoreAfterBytes < 0 || m.cfg.RestoreAfterBytes > math.MaxUint32 {
		return gecitbpf.Config{}, fmt.Errorf("restore-after-bytes out of range for BPF config: %d", m.cfg.RestoreAfterBytes)
	}
	return gecitbpf.Config{
		MSS:               uint16(m.cfg.MSS),               // #nosec G115 -- range checked above.
		RestoreMSS:        uint16(m.cfg.RestoreMSS),        // #nosec G115 -- range checked above.
		RestoreAfterBytes: uint32(m.cfg.RestoreAfterBytes), // #nosec G115 -- range checked above.
		Enabled:           enabled,
	}, nil
}
