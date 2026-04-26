package engine

type Config struct {
	MSS                 int      `yaml:"mss" mapstructure:"mss"`
	RestoreMSS          int      `yaml:"restore_mss" mapstructure:"restore_mss"`
	RestoreAfterBytes   int      `yaml:"restore_after_bytes" mapstructure:"restore_after_bytes"`
	Ports               []uint16 `yaml:"ports" mapstructure:"ports"`
	Interface           string   `yaml:"interface" mapstructure:"interface"`
	CgroupPath          string   `yaml:"cgroup_path" mapstructure:"cgroup_path"`
	FakeTTL             int      `yaml:"fake_ttl" mapstructure:"fake_ttl"`
	DoHEnabled          bool     `yaml:"doh_enabled" mapstructure:"doh_enabled"`
	DoHUpstream         string   `yaml:"doh_upstream" mapstructure:"doh_upstream"`
	AllowPlainDoH       bool     `yaml:"allow_plain_doh" mapstructure:"allow_plain_doh"`
	AllowPrivateTargets bool     `yaml:"allow_private_targets" mapstructure:"allow_private_targets"`
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
	}
}
