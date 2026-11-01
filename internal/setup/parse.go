package setup

import (
	"fmt"
	"strconv"
	"strings"

	"dnsupdate/internal/config"
)

// Fields are the text values edited by the wizard and the setup flags.
type Fields struct {
	Server       string
	Port         string
	Zone         string
	Domain       string
	TTL          string
	Interval     string
	KeyName      string
	KeyAlgorithm string
	KeySecret    string
	KeyFile      string
}

// FromConfig copies cfg into form fields, filling defaults for empty optional values.
func FromConfig(cfg config.Config) Fields {
	if cfg.Port == 0 {
		cfg.Port = config.Defaults().Port
	}
	if cfg.TTL == 0 {
		cfg.TTL = config.Defaults().TTL
	}
	if strings.TrimSpace(cfg.Interval) == "" {
		cfg.Interval = config.Defaults().Interval
	}
	if strings.TrimSpace(cfg.KeyAlgorithm) == "" {
		cfg.KeyAlgorithm = config.Defaults().KeyAlgorithm
	}
	return Fields{
		Server:       cfg.Server,
		Port:         strconv.Itoa(cfg.Port),
		Zone:         cfg.Zone,
		Domain:       cfg.Domain,
		TTL:          strconv.FormatUint(uint64(cfg.TTL), 10),
		Interval:     cfg.Interval,
		KeyName:      cfg.KeyName,
		KeyAlgorithm: cfg.KeyAlgorithm,
		KeySecret:    cfg.KeySecret,
		KeyFile:      cfg.KeyFile,
	}
}

// Parse converts fields into a validated config.
func Parse(f Fields) (config.Config, error) {
	port, err := strconv.Atoi(strings.TrimSpace(f.Port))
	if err != nil {
		return config.Config{}, fmt.Errorf("port: must be a number")
	}
	ttl, err := strconv.ParseUint(strings.TrimSpace(f.TTL), 10, 32)
	if err != nil {
		return config.Config{}, fmt.Errorf("ttl: must be a number")
	}
	cfg := config.Config{
		Server:       strings.TrimSpace(f.Server),
		Port:         port,
		Zone:         strings.TrimSpace(f.Zone),
		Domain:       strings.TrimSpace(f.Domain),
		TTL:          uint32(ttl),
		Interval:     strings.TrimSpace(f.Interval),
		KeyName:      strings.TrimSpace(f.KeyName),
		KeyAlgorithm: strings.TrimSpace(f.KeyAlgorithm),
		KeySecret:    strings.TrimSpace(f.KeySecret),
		KeyFile:      strings.TrimSpace(f.KeyFile),
	}
	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}
