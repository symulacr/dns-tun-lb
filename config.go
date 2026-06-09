package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type DefaultDNSBehaviorMode string

const (
	DefaultDNSModeForward DefaultDNSBehaviorMode = "forward"
)

type DefaultDNSBehavior struct {
	Mode           DefaultDNSBehaviorMode `yaml:"mode"`
	ForwardResolver string                `yaml:"forward_resolver"`
}

type GlobalConfig struct {
	ListenAddress      string             `yaml:"listen_address"`
	MetricsListen      string             `yaml:"metrics_listen"`
	ReadTimeout        string             `yaml:"read_timeout"`
	MaxConcurrent      int                `yaml:"max_concurrent"`
	Direct             bool               `yaml:"direct"`                 // bypass worker pool, direct goroutine-per-pkt
	PoolBypassThreshold int               `yaml:"pool_bypass_threshold"`  // auto-bypass below this concurrency
	DefaultDNSBehavior DefaultDNSBehavior `yaml:"default_dns_behavior"`
	FireAndForget bool `yaml:"fire_and_forget"`
	ReusePort int `yaml:"reuse_port"`  // number of SO_REUSEPORT listeners (0=disabled)
}

type BackendConfig struct {
	ID      string `yaml:"id,omitempty"`
	Address string `yaml:"address,omitempty"`
	LbID    *uint8 `yaml:"lb_id"`
	parsedAddr *net.UDPAddr
}

type PoolConfig struct {
	Name         string          `yaml:"name"`
	DomainSuffix string          `yaml:"domain_suffix"`
	Backends     []BackendConfig `yaml:"backends"`
}

type ProtocolPoolsConfig struct {
	Pools []PoolConfig `yaml:"pools"`
}

type ProtocolsConfig struct {
	Dnstt      ProtocolPoolsConfig `yaml:"dnstt"`
	Slipstream ProtocolPoolsConfig `yaml:"slipstream"`
	Noizdns    ProtocolPoolsConfig `yaml:"noizdns"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type Config struct {
	Global    GlobalConfig    `yaml:"global"`
	Protocols ProtocolsConfig `yaml:"protocols"`
	Logging   LoggingConfig   `yaml:"logging"`

	parsedReadTimeout time.Duration
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Global.MetricsListen = strings.TrimSpace(cfg.Global.MetricsListen)
	if d, err := time.ParseDuration(cfg.Global.ReadTimeout); err == nil && d > 0 {
		cfg.parsedReadTimeout = d
	} else {
		cfg.parsedReadTimeout = 2 * time.Second
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	var errs []error
	if c.Global.ListenAddress == "" {
		errs = append(errs, errors.New("listen_address is required"))
	}
	// Validate ReadTimeout: empty (will default), "-1" (unlimited), or a positive duration.
	if c.Global.ReadTimeout != "" {
		if c.Global.ReadTimeout == "-1" {
		} else if d, err := time.ParseDuration(c.Global.ReadTimeout); err != nil {
			errs = append(errs, fmt.Errorf("read_timeout %q: invalid duration", c.Global.ReadTimeout))
		} else if d <= 0 {
			errs = append(errs, fmt.Errorf("read_timeout %q: must be positive or -1", c.Global.ReadTimeout))
		}
	}
	// Validate MaxConcurrent >= 0 (0 means no limit).
	if c.Global.MaxConcurrent < 0 {
		errs = append(errs, fmt.Errorf("max_concurrent %d: must be >= 0", c.Global.MaxConcurrent))
	}
	allPools := c.Protocols.Dnstt.Pools
	allPools = append(allPools, c.Protocols.Slipstream.Pools...)
	allPools = append(allPools, c.Protocols.Noizdns.Pools...)
	if len(allPools) == 0 && c.Global.DefaultDNSBehavior.ForwardResolver == "" {
		errs = append(errs, errors.New("at least one pool or forward_resolver required"))
	}
	for _, p := range allPools {
		if p.DomainSuffix == "" {
			errs = append(errs, fmt.Errorf("pool %q: domain_suffix is required", p.Name))
		}
		if len(p.Backends) == 0 {
			errs = append(errs, fmt.Errorf("pool %q: at least one backend required", p.Name))
		}
		for _, b := range p.Backends {
			if b.Address == "" {
				errs = append(errs, fmt.Errorf("pool %q backend %q: address is required", p.Name, b.ID))
			} else {
				host, _, err := net.SplitHostPort(b.Address)
				if err != nil {
					errs = append(errs, fmt.Errorf("pool %q backend %q: address %q: %v", p.Name, b.ID, b.Address, err))
				} else if net.ParseIP(host) == nil {
					errs = append(errs, fmt.Errorf("pool %q backend %q: address %q: invalid IP %q", p.Name, b.ID, b.Address, host))
				}
			}
		}
	}
	return errors.Join(errs...)
}

