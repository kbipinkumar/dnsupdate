package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const fixtureSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

func testSecret(t *testing.T) string {
	t.Helper()
	return fixtureSecret
}

func sample() Config {
	cfg := Defaults()
	cfg.Server = "192.0.2.53"
	cfg.Zone = "example.com"
	cfg.Domain = "example.com"
	cfg.KeyName = "ddns-key"
	cfg.KeySecret = fixtureSecret
	return cfg
}

func TestCheckMode(t *testing.T) {
	if err := CheckMode(0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckMode(0400); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0644, 0606, 0660, 0707} {
		if err := CheckMode(mode); err == nil {
			t.Fatalf("mode %#o was accepted", mode)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	cfg := sample()
	cfg.KeySecret = testSecret(t)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("mode = %#o, want 0600", info.Mode().Perm())
		}
		dirInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dirInfo.Mode().Perm()&0077 != 0 {
			t.Fatalf("directory mode = %#o", dirInfo.Mode().Perm())
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeySecret != cfg.KeySecret || got.Server != cfg.Server || got.Zone != cfg.Zone {
		t.Fatalf("loaded %+v", got)
	}
}

func TestLoadRejectsLooseMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not enforced on windows")
	}
	cfg := sample()
	cfg.KeySecret = testSecret(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	text, err := Format(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected permission error")
	}
}

func TestRedactedOmitsSecret(t *testing.T) {
	cfg := sample()
	cfg.KeySecret = testSecret(t)
	text, err := Format(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, cfg.KeySecret) {
		t.Fatalf("redacted config contains the secret:\n%s", text)
	}
	if !strings.Contains(text, `key_secret = "***"`) && !strings.Contains(text, "key_secret = '***'") {
		t.Fatalf("redacted secret marker missing:\n%s", text)
	}
}

func TestParseBINDKey(t *testing.T) {
	secret := testSecret(t)
	in := `
key "local-ddns-key" {
    algorithm hmac-sha256;
    secret "` + secret + `";
};
`
	name, algo, got, err := ParseBINDKey(in)
	if err != nil {
		t.Fatal(err)
	}
	if name != "local-ddns-key" || algo != "hmac-sha256" || got != secret {
		t.Fatalf("name=%s algo=%s secret=%s", name, algo, got)
	}

	quoted := "key \"k\" {\n algorithm \"hmac-sha512\";\n secret \"" + secret + "\";\n};\n"
	_, algo, _, err = ParseBINDKey(quoted)
	if err != nil {
		t.Fatal(err)
	}
	if algo != "hmac-sha512" {
		t.Fatalf("algo %s", algo)
	}
	if _, _, _, err := ParseBINDKey("key \"k\" { algorithm hmac-sha256; };"); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestResolveKeyFileOverridesInline(t *testing.T) {
	fileSecret := testSecret(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "Kexample.key")
	body := "key \"from-file\" {\n    algorithm hmac-sha256;\n    secret \"" + fileSecret + "\";\n};\n"
	if err := os.WriteFile(keyPath, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := sample()
	cfg.KeySecret = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	cfg.KeyName = "inline-name"
	cfg.KeyAlgorithm = "hmac-sha1"
	cfg.KeyFile = "Kexample.key"
	got, err := cfg.Resolve(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != fileSecret {
		t.Fatalf("secret from inline was used")
	}
	if got.KeyName != dns.CanonicalName("from-file") {
		t.Fatalf("key name %s", got.KeyName)
	}
	if got.Algorithm != dns.HmacSHA256 {
		t.Fatalf("algorithm %s", got.Algorithm)
	}
	if got.Zone != "example.com." || got.Domain != "example.com." {
		t.Fatalf("names %s %s", got.Zone, got.Domain)
	}
}

func TestNormalizeAlgorithm(t *testing.T) {
	got, err := NormalizeAlgorithm("HMAC-SHA256")
	if err != nil {
		t.Fatal(err)
	}
	if got != dns.HmacSHA256 {
		t.Fatalf("got %s", got)
	}
	if _, err := NormalizeAlgorithm("hmac-md5"); err == nil {
		t.Fatal("expected unsupported algorithm")
	}
}

func TestValidate(t *testing.T) {
	cfg := sample()
	cfg.KeySecret = testSecret(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Server = "dns.example"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected server error")
	}
	cfg = sample()
	cfg.KeySecret = testSecret(t)
	cfg.Interval = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected interval error")
	}
}

func TestSystemdInterval(t *testing.T) {
	if got := SystemdInterval(5 * time.Minute); got != "5min" {
		t.Fatalf("got %s", got)
	}
	if got := SystemdInterval(2 * time.Hour); got != "2h" {
		t.Fatalf("got %s", got)
	}
	if got := SystemdInterval(90 * time.Second); got != "90s" {
		t.Fatalf("got %s", got)
	}
}
