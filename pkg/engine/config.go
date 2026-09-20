package engine

// The json tags carry the panel's wire format. They match the config file keys
// so the same name means the same setting in the file, the API and the UI.
type Config struct {
	MSS               int      `yaml:"mss" mapstructure:"mss" json:"mss"`
	RestoreMSS        int      `yaml:"restore_mss" mapstructure:"restore_mss" json:"restore_mss"`
	RestoreAfterBytes int      `yaml:"restore_after_bytes" mapstructure:"restore_after_bytes" json:"restore_after_bytes"`
	Ports             []uint16 `yaml:"ports" mapstructure:"ports" json:"ports"`
	Interface         string   `yaml:"interface" mapstructure:"interface" json:"interface"`
	CgroupPath        string   `yaml:"cgroup_path" mapstructure:"cgroup_path" json:"cgroup_path"`
	FakeTTL           int      `yaml:"fake_ttl" mapstructure:"fake_ttl" json:"fake_ttl"`
	DoHEnabled        bool     `yaml:"doh_enabled" mapstructure:"doh_enabled" json:"doh_enabled"`
	DoHUpstream       string   `yaml:"doh_upstream" mapstructure:"doh_upstream" json:"doh_upstream"`
	Verbose           bool     `yaml:"verbose" mapstructure:"verbose" json:"verbose"`
	PanelEnabled      bool     `yaml:"panel_enabled" mapstructure:"panel_enabled" json:"panel_enabled"`
	PanelAddr         string   `yaml:"panel_addr" mapstructure:"panel_addr" json:"panel_addr"`
}

func DefaultConfig() Config {
	return Config{
		MSS:               88,
		RestoreMSS:        0,
		RestoreAfterBytes: 600,
		Ports:             []uint16{443},
		CgroupPath:        "/sys/fs/cgroup",
		FakeTTL:           8,
		DoHEnabled:        true,
		DoHUpstream:       "cloudflare",
		PanelEnabled:      true,
		PanelAddr:         "127.0.0.1:8088",
	}
}
