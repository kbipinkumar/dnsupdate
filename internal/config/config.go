package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
)

const DefaultPath = "/etc/dnsupdate/config.toml"

// Config is the on-disk configuration. KeySecret is never written to logs.
type Config struct {
	Server       string `toml:"server"`
	Port         int    `toml:"port"`
	Zone         string `toml:"zone"`
	Domain       string `toml:"domain"`
	TTL          uint32 `toml:"ttl"`
	Interval     string `toml:"interval"`
	KeyName      string `toml:"key_name"`
	KeyAlgorithm string `toml:"key_algorithm"`
	KeySecret    string `toml:"key_secret"`
	KeyFile      string `toml:"key_file"`
}

// Resolved is a validated config with the TSIG material ready to use.
type Resolved struct {
	Server    netip.Addr
	Port      int
	Zone      string
	Domain    string
	TTL       uint32
	Interval  time.Duration
	KeyName   string
	Algorithm string
	Secret    string
}

func Defaults() Config {
	return Config{
		Port:         53,
		TTL:          3600,
		Interval:     "5m",
		KeyAlgorithm: "hmac-sha256",
	}
}

// PathFrom returns flag, then DNSUPDATE_CONFIG, then DefaultPath.
func PathFrom(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("DNSUPDATE_CONFIG"); env != "" {
		return env
	}
	return DefaultPath
}

// CheckMode reports whether mode is owner-only.
func CheckMode(mode os.FileMode) error {
	perm := mode.Perm()
	if perm&0077 != 0 {
		return fmt.Errorf("group or world accessible (mode %#o); expected 0600", perm)
	}
	return nil
}

func enforcePrivateMode() bool {
	return runtime.GOOS != "windows"
}

// Load reads path and refuses group- or world-accessible files on Unix.
func Load(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("%s: not a regular file", path)
	}
	if enforcePrivateMode() {
		if err := CheckMode(info.Mode()); err != nil {
			return Config{}, fmt.Errorf("%s: %w", path, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return decode(data)
}

// Read loads path without the permission check so setup can prefill a form.
func Read(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return decode(data)
}

func decode(data []byte) (Config, error) {
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes cfg as TOML with mode 0600. The parent directory is mode 0700.
func Save(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil && runtime.GOOS != "windows" {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(path, 0600); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

// Redacted returns a copy with the TSIG secret replaced.
func (c Config) Redacted() Config {
	out := c
	if out.KeySecret != "" {
		out.KeySecret = "***"
	}
	return out
}

// Format encodes cfg as TOML.
func Format(cfg Config) (string, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Validate checks fields that are stored in the file.
// A key file may supply the TSIG name, algorithm, and secret later.
func (c Config) Validate() error {
	if _, err := netip.ParseAddr(strings.TrimSpace(c.Server)); err != nil {
		return fmt.Errorf("server: must be an IP address")
	}
	server := netip.MustParseAddr(strings.TrimSpace(c.Server))
	if server.IsUnspecified() || server.IsMulticast() {
		return fmt.Errorf("server: must be a unicast IP address")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port: must be between 1 and 65535")
	}
	if err := domain(c.Zone, "zone"); err != nil {
		return err
	}
	if err := domain(c.Domain, "domain"); err != nil {
		return err
	}
	if c.TTL == 0 {
		return fmt.Errorf("ttl: must be greater than 0")
	}
	interval, err := time.ParseDuration(strings.TrimSpace(c.Interval))
	if err != nil {
		return fmt.Errorf("interval: %w", err)
	}
	if interval <= 0 {
		return fmt.Errorf("interval: must be greater than 0")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		if strings.TrimSpace(c.KeyName) == "" {
			return fmt.Errorf("key name is required when key file is empty")
		}
		if _, err := NormalizeAlgorithm(c.KeyAlgorithm); err != nil {
			return err
		}
		if err := validateSecret(c.KeySecret); err != nil {
			return err
		}
	} else if strings.TrimSpace(c.KeyAlgorithm) != "" {
		if _, err := NormalizeAlgorithm(c.KeyAlgorithm); err != nil {
			return err
		}
	}
	return nil
}

func domain(name, field string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("%s: required", field)
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return fmt.Errorf("%s: invalid domain name", field)
	}
	return nil
}

func validateSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return fmt.Errorf("key secret is required when key file is empty")
	}
	if _, err := decodeSecret(secret); err != nil {
		return fmt.Errorf("key secret: must be base64")
	}
	return nil
}

// Resolve validates cfg and loads the BIND key file when KeyFile is set.
// Relative key file paths are resolved against the directory of configPath.
func (c Config) Resolve(configPath string) (Resolved, error) {
	if err := c.Validate(); err != nil {
		return Resolved{}, err
	}
	server := netip.MustParseAddr(strings.TrimSpace(c.Server))
	interval, err := time.ParseDuration(strings.TrimSpace(c.Interval))
	if err != nil {
		return Resolved{}, err
	}
	name := strings.TrimSpace(c.KeyName)
	algo := strings.TrimSpace(c.KeyAlgorithm)
	secret := strings.TrimSpace(c.KeySecret)

	keyPath := strings.TrimSpace(c.KeyFile)
	if keyPath != "" {
		if !filepath.IsAbs(keyPath) && configPath != "" {
			keyPath = filepath.Join(filepath.Dir(configPath), keyPath)
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return Resolved{}, fmt.Errorf("key file: %w", err)
		}
		parsedName, parsedAlgo, parsedSecret, err := ParseBINDKey(string(data))
		if err != nil {
			return Resolved{}, fmt.Errorf("key file: %w", err)
		}
		name = parsedName
		algo = parsedAlgo
		secret = parsedSecret
	}

	normAlgo, err := NormalizeAlgorithm(algo)
	if err != nil {
		return Resolved{}, err
	}
	if _, err := decodeSecret(secret); err != nil {
		return Resolved{}, fmt.Errorf("key secret: must be base64")
	}
	if name == "" {
		return Resolved{}, fmt.Errorf("key name is required")
	}

	return Resolved{
		Server:    server,
		Port:      c.Port,
		Zone:      dns.Fqdn(strings.TrimSpace(c.Zone)),
		Domain:    dns.Fqdn(strings.TrimSpace(c.Domain)),
		TTL:       c.TTL,
		Interval:  interval,
		KeyName:   dns.CanonicalName(name),
		Algorithm: normAlgo,
		Secret:    stripSpace(secret),
	}, nil
}

// NormalizeAlgorithm maps a config value to a miekg/dns TSIG algorithm name.
func NormalizeAlgorithm(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	switch s {
	case "hmac-sha1":
		return dns.HmacSHA1, nil
	case "hmac-sha224":
		return dns.HmacSHA224, nil
	case "hmac-sha256":
		return dns.HmacSHA256, nil
	case "hmac-sha384":
		return dns.HmacSHA384, nil
	case "hmac-sha512":
		return dns.HmacSHA512, nil
	case "":
		return "", fmt.Errorf("key algorithm is required")
	default:
		return "", fmt.Errorf("unsupported key algorithm %q", s)
	}
}

// SystemdInterval formats d as a systemd time span.
func SystemdInterval(d time.Duration) string {
	if d <= 0 {
		return "5min"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dmin", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}
