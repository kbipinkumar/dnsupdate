package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderUnits(t *testing.T) {
	service, timer := Render("/usr/local/bin/dnsupdate", "/etc/dnsupdate/config.toml", 5*time.Minute)
	for _, want := range []string{
		"After=network-online.target",
		"Wants=network-online.target",
		"Type=oneshot",
		"ExecStart=/usr/local/bin/dnsupdate run --config /etc/dnsupdate/config.toml",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service missing %q\n%s", want, service)
		}
	}
	for _, want := range []string{
		"OnBootSec=1min",
		"OnUnitActiveSec=5min",
		"Persistent=true",
		"WantedBy=timers.target",
	} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer missing %q\n%s", want, timer)
		}
	}
	if strings.Contains(service+timer, "key_secret") {
		t.Fatal("unit files contain key material")
	}
}

func TestRenderQuotesSpaces(t *testing.T) {
	service, _ := Render("/opt/dns update/dnsupdate", "/etc/my config.toml", time.Minute)
	if !strings.Contains(service, `ExecStart="/opt/dns update/dnsupdate" run --config "/etc/my config.toml"`) {
		t.Fatalf("service: %s", service)
	}
}

func TestApplyWritesUnits(t *testing.T) {
	dir := t.TempDir()
	if err := Apply(dir, "/usr/local/bin/dnsupdate", "/etc/dnsupdate/config.toml", 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dnsupdate.service", "dnsupdate.timer"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}
