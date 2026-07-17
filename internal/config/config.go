// Package config loads openconnectd's daemon settings from a YAML file and/or
// environment, with sane localhost-only defaults (callers reach this daemon
// over loopback, never publicly).
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen is the daemon's own HTTP API bind. Loopback by default — callers
	// dial it locally; exposing it publicly would hand out VPN admin with a
	// single bearer token.
	Listen string `yaml:"listen"`
	// Token is the bearer required on every request. Empty ⇒ generated once
	// and written to TokenFile on first boot.
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`

	// OcservBin/OcctlBin/OcpasswdBin are the ocserv tools; empty ⇒ resolved
	// from PATH at call time.
	OcservBin   string `yaml:"ocserv_bin"`
	OcctlBin    string `yaml:"occtl_bin"`
	OcpasswdBin string `yaml:"ocpasswd_bin"`

	// Dirs the daemon owns.
	StateDir  string `yaml:"state_dir"`  // instances + client records
	ConfigDir string `yaml:"config_dir"` // rendered ocserv.conf per instance
	PKIDir    string `yaml:"pki_dir"`    // CA + issued certs
	RunDir    string `yaml:"run_dir"`    // sockets

	// MetricsListen exposes Prometheus /metrics separately (loopback).
	MetricsListen string `yaml:"metrics_listen"`
}

func Default() Config {
	return Config{
		Listen:        "127.0.0.1:51990",
		TokenFile:     "/etc/openconnectd/token",
		StateDir:      "/var/lib/openconnectd/state",
		ConfigDir:     "/etc/openconnectd/instances",
		PKIDir:        "/var/lib/openconnectd/pki",
		RunDir:        "/run/openconnectd",
		MetricsListen: "127.0.0.1:9093",
	}
}

// Load reads path (if non-empty) over the defaults. Missing file with an empty
// path is fine — you get defaults.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return c, nil
}
