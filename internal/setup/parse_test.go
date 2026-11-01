package setup

import (
	"testing"

	"dnsupdate/internal/config"
)

func TestParseAcceptsSecret(t *testing.T) {
	cfg, err := Parse(Fields{
		Server:       "192.0.2.53",
		Port:         "53",
		Zone:         "example.com",
		Domain:       "host.example.com",
		TTL:          "3600",
		Interval:     "5m",
		KeyName:      "ddns-key",
		KeyAlgorithm: "hmac-sha256",
		KeySecret:    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "host.example.com" || cfg.TTL != 3600 {
		t.Fatalf("%+v", cfg)
	}
}

func TestParseRequiresSecretOrKeyFile(t *testing.T) {
	_, err := Parse(Fields{
		Server:       "192.0.2.53",
		Port:         "53",
		Zone:         "example.com",
		Domain:       "example.com",
		TTL:          "3600",
		Interval:     "5m",
		KeyName:      "ddns-key",
		KeyAlgorithm: "hmac-sha256",
	})
	if err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestFromConfigDefaults(t *testing.T) {
	f := FromConfig(config.Config{})
	if f.Port != "53" || f.TTL != "3600" || f.Interval != "5m" || f.KeyAlgorithm != "hmac-sha256" {
		t.Fatalf("%+v", f)
	}
}
