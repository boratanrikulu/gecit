//go:build linux

package ebpf

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

// gecitConfig must match struct gecit_config_t in maps.h exactly.
// Field order, sizes, and padding must be identical.
type gecitConfig struct {
	MSS               uint16
	RestoreMSS        uint16
	RestoreAfterBytes uint32
	Enabled           uint8
	Reserved          [7]uint8
}

func (m *Manager) pushConfig() error {
	configMap := m.collection.Maps["gecit_config"]
	if configMap == nil {
		return errMapNotFound("gecit_config")
	}

	cfg, err := m.bpfConfig(1)
	if err != nil {
		return err
	}

	key := uint32(0)
	return configMap.Update(key, cfg, ebpf.UpdateAny)
}

func (m *Manager) pushTargetPorts() error {
	portsMap := m.collection.Maps["target_ports"]
	if portsMap == nil {
		return errMapNotFound("target_ports")
	}

	val := uint8(1)
	for _, port := range m.cfg.Ports {
		if err := portsMap.Update(port, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) pushExcludeIPs() error {
	excludeMap := m.collection.Maps["exclude_ips"]
	if excludeMap == nil {
		return nil // map not present in older BPF objects
	}

	val := uint8(1)
	for _, ip := range m.cfg.ExcludeIPs {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		// Network byte order — same as skops->remote_ip4.
		key := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
		if err := excludeMap.Update(key, val, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// UpdateEnabled updates the enabled state at runtime without reloading BPF.
func (m *Manager) UpdateEnabled(enabled bool) error {
	configMap := m.collection.Maps["gecit_config"]
	if configMap == nil {
		return errMapNotFound("gecit_config")
	}

	e := uint8(0)
	if enabled {
		e = 1
	}

	cfg, err := m.bpfConfig(e)
	if err != nil {
		return err
	}

	key := uint32(0)
	return configMap.Update(key, cfg, ebpf.UpdateAny)
}

func (m *Manager) bpfConfig(enabled uint8) (gecitConfig, error) {
	if m.cfg.MSS < 1 || m.cfg.MSS > math.MaxUint16 {
		return gecitConfig{}, fmt.Errorf("MSS out of range for BPF config: %d", m.cfg.MSS)
	}
	if m.cfg.RestoreMSS < 0 || m.cfg.RestoreMSS > math.MaxUint16 {
		return gecitConfig{}, fmt.Errorf("restore MSS out of range for BPF config: %d", m.cfg.RestoreMSS)
	}
	if m.cfg.RestoreAfterBytes < 0 || m.cfg.RestoreAfterBytes > math.MaxUint32 {
		return gecitConfig{}, fmt.Errorf("restore-after-bytes out of range for BPF config: %d", m.cfg.RestoreAfterBytes)
	}
	return gecitConfig{
		MSS:               uint16(m.cfg.MSS),               // #nosec G115 -- range checked above.
		RestoreMSS:        uint16(m.cfg.RestoreMSS),        // #nosec G115 -- range checked above.
		RestoreAfterBytes: uint32(m.cfg.RestoreAfterBytes), // #nosec G115 -- range checked above.
		Enabled:           enabled,
	}, nil
}
