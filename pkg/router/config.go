package router

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// QueueBackend identifies the interception backend used by router mode.
type QueueBackend string

const (
	QueueBackendNFQueue QueueBackend = "nfqueue"
	QueueBackendDryRun  QueueBackend = "dryrun"
)

// Config is the planned configuration surface for a router-wide mode.
type Config struct {
	WANInterface     string
	LANInterfaces    []string
	TableName        string
	Backend          QueueBackend
	QueueNum         uint16
	PacketMark       uint32
	TCPPorts         []uint16
	UDPPorts         []uint16
	FakeTTL          int
	MaxFlows         int
	ProbeTargets     []string
	AutoHostlistPath string
	EnableQUIC       bool
	EnablePostNAT    bool
}

var tableNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

// DefaultConfig returns conservative defaults for the NFQUEUE router mode.
func DefaultConfig() Config {
	return Config{
		TableName:     "gecit_router",
		Backend:       QueueBackendNFQueue,
		QueueNum:      200,
		PacketMark:    0x40000000,
		TCPPorts:      []uint16{443},
		UDPPorts:      []uint16{443},
		FakeTTL:       8,
		MaxFlows:      4096,
		ProbeTargets:  []string{"discord.com", "youtube.com"},
		EnableQUIC:    false,
		EnablePostNAT: true,
	}
}

// Normalized fills zero-value fields with conservative defaults.
func (c Config) Normalized() Config {
	def := DefaultConfig()

	if c.WANInterface == "" {
		c.WANInterface = strings.TrimSpace(def.WANInterface)
	} else {
		c.WANInterface = strings.TrimSpace(c.WANInterface)
	}
	c.LANInterfaces = trimStrings(c.LANInterfaces)

	if c.TableName == "" {
		c.TableName = def.TableName
	}
	if c.Backend == "" {
		c.Backend = def.Backend
	}
	if c.QueueNum == 0 {
		c.QueueNum = def.QueueNum
	}
	if c.PacketMark == 0 {
		c.PacketMark = def.PacketMark
	}
	if len(c.TCPPorts) == 0 {
		c.TCPPorts = append([]uint16(nil), def.TCPPorts...)
	}
	if len(c.UDPPorts) == 0 {
		c.UDPPorts = append([]uint16(nil), def.UDPPorts...)
	}
	if c.FakeTTL == 0 {
		c.FakeTTL = def.FakeTTL
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = def.MaxFlows
	}
	c.ProbeTargets = trimStrings(c.ProbeTargets)
	if len(c.ProbeTargets) == 0 {
		c.ProbeTargets = append([]string(nil), def.ProbeTargets...)
	}

	return c
}

// Validate checks whether the router-mode config is sane enough for dry-run rendering.
func (c Config) Validate() error {
	c = c.Normalized()

	switch c.Backend {
	case QueueBackendNFQueue, QueueBackendDryRun:
	default:
		return fmt.Errorf("unsupported router backend %q", c.Backend)
	}
	if c.WANInterface == "" {
		return errors.New("wan interface is required")
	}
	if !tableNameRE.MatchString(c.TableName) {
		return fmt.Errorf("invalid nftables table name %q", c.TableName)
	}
	if err := validatePorts("tcp", c.TCPPorts); err != nil {
		return err
	}
	if c.EnableQUIC {
		if err := validatePorts("udp", c.UDPPorts); err != nil {
			return err
		}
	}
	if len(c.TCPPorts) == 0 && (!c.EnableQUIC || len(c.UDPPorts) == 0) {
		return errors.New("at least one target port is required")
	}
	if c.FakeTTL < 1 || c.FakeTTL > 255 {
		return fmt.Errorf("fake TTL must be between 1 and 255, got %d", c.FakeTTL)
	}
	if c.MaxFlows < 1 {
		return fmt.Errorf("max flows must be >= 1, got %d", c.MaxFlows)
	}

	return nil
}

func validatePorts(proto string, ports []uint16) error {
	for _, port := range ports {
		if port == 0 {
			return fmt.Errorf("%s port 0 is not valid", proto)
		}
	}
	return nil
}

func trimStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}
