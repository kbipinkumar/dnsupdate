package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsupdate/internal/config"
)

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	runErr := fn()
	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String(), runErr
}

func TestSetupGenerateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	out, err := captureStdout(t, func() error {
		return cmdSetup([]string{
			"--non-interactive",
			"--config", path,
			"--server", "192.0.2.53",
			"--zone", "example.com",
			"--domain", "host.example.com",
			"--key-name", "ddns-key",
			"--key-algorithm", "hmac-sha512",
			"--generate-key",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(cfg.KeySecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("decoded length = %d, want 64", len(raw))
	}
	if !strings.Contains(out, cfg.KeySecret) {
		t.Fatal("generated secret was not printed")
	}
	if strings.Count(out, cfg.KeySecret) != 1 {
		t.Fatalf("secret printed %d times", strings.Count(out, cfg.KeySecret))
	}
}

func TestSetupGenerateKeyConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	err := cmdSetup([]string{
		"--non-interactive",
		"--config", path,
		"--generate-key",
		"--key-secret", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	})
	if err == nil || !strings.Contains(err.Error(), "--generate-key") {
		t.Fatalf("got %v", err)
	}

	existing := config.Defaults()
	existing.Server = "192.0.2.53"
	existing.Zone = "example.com"
	existing.Domain = "host.example.com"
	existing.KeyName = "ddns-key"
	existing.KeyFile = "Kexample.key"
	if err := config.Save(path, existing); err != nil {
		t.Fatal(err)
	}
	err = cmdSetup([]string{
		"--non-interactive",
		"--config", path,
		"--generate-key",
	})
	if err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("got %v", err)
	}

	err = cmdSetup([]string{
		"--non-interactive",
		"--config", path,
		"--generate-key",
		"--key-file", "Kexample.key",
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined with --key-secret or --key-file") {
		t.Fatalf("got %v", err)
	}
}
