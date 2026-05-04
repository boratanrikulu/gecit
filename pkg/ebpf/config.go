//go:build linux

package ebpf

import (
	gecitbpf "github.com/boratanrikulu/gecit/pkg/ebpf/bpf"
	"github.com/cilium/ebpf"
)

func (m *Manager) pushConfig() error {
	cfg := gecitbpf.Config{
		MSS:               uint16(m.cfg.MSS),
		RestoreMSS:        uint16(m.cfg.RestoreMSS),
		RestoreAfterBytes: uint32(m.cfg.RestoreAfterBytes),
		Enabled:           1,
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
	cfg := gecitbpf.Config{
		MSS:               uint16(m.cfg.MSS),
		RestoreMSS:        uint16(m.cfg.RestoreMSS),
		RestoreAfterBytes: uint32(m.cfg.RestoreAfterBytes),
		Enabled:           e,
	}
	key := uint32(0)
	return m.objs.ConfigMap.Update(key, cfg, ebpf.UpdateAny)
}
