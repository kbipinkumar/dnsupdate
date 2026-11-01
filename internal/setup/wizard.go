package setup

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"dnsupdate/internal/config"
)

// Wizard edits f with a form. Flags should already be copied into f.
// configPath is used to resolve a relative BIND key file.
func Wizard(f *Fields, configPath string) error {
	if norm, err := config.NormalizeAlgorithm(f.KeyAlgorithm); err == nil {
		f.KeyAlgorithm = strings.TrimSuffix(norm, ".")
	} else {
		f.KeyAlgorithm = config.Defaults().KeyAlgorithm
	}

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("DNS server IP").Value(&f.Server).Validate(required("server")),
			huh.NewInput().Title("DNS server port").Value(&f.Port).Validate(validPort),
			huh.NewInput().Title("Zone").Value(&f.Zone).Validate(required("zone")),
			huh.NewInput().Title("Domain").Value(&f.Domain).Validate(required("domain")),
			huh.NewInput().Title("TTL (seconds)").Value(&f.TTL).Validate(validTTL),
			huh.NewInput().Title("Update interval (for example 5m)").Value(&f.Interval).Validate(validInterval),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("BIND key file (optional)").
				Description("When set, this file overrides the key name, algorithm, and secret.").
				Value(&f.KeyFile).
				Validate(func(s string) error { return validKeyFile(s, configPath) }),
			huh.NewInput().Title("TSIG key name").Value(&f.KeyName).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" && strings.TrimSpace(f.KeyFile) == "" {
					return fmt.Errorf("key name is required unless a key file is set")
				}
				return nil
			}),
			huh.NewSelect[string]().
				Title("TSIG algorithm").
				Options(
					huh.NewOption("hmac-sha256", "hmac-sha256"),
					huh.NewOption("hmac-sha1", "hmac-sha1"),
					huh.NewOption("hmac-sha224", "hmac-sha224"),
					huh.NewOption("hmac-sha384", "hmac-sha384"),
					huh.NewOption("hmac-sha512", "hmac-sha512"),
				).
				Value(&f.KeyAlgorithm),
			huh.NewInput().
				Title("TSIG secret (base64)").
				EchoMode(huh.EchoModePassword).
				Value(&f.KeySecret).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" && strings.TrimSpace(f.KeyFile) == "" {
						return fmt.Errorf("TSIG secret or key file is required")
					}
					if strings.TrimSpace(s) == "" {
						return nil
					}
					if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err != nil {
						return fmt.Errorf("secret must be base64")
					}
					return nil
				}),
		),
	)
	if err := form.Run(); err != nil {
		return err
	}
	return nil
}

func required(field string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

func validPort(s string) error {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validTTL(s string) error {
	ttl, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil || ttl == 0 {
		return fmt.Errorf("ttl must be a positive integer")
	}
	return nil
}

func validInterval(s string) error {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return fmt.Errorf("interval must be a duration such as 5m")
	}
	return nil
}

func validKeyFile(s, configPath string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !filepath.IsAbs(s) && configPath != "" {
		s = filepath.Join(filepath.Dir(configPath), s)
	}
	data, err := os.ReadFile(s)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	if _, _, _, err := config.ParseBINDKey(string(data)); err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	return nil
}
