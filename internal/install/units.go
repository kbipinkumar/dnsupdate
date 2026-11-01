package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dnsupdate/internal/config"
)

const (
	UnitDir     = "/etc/systemd/system"
	serviceName = "dnsupdate.service"
	timerName   = "dnsupdate.timer"
)

// Render returns the systemd service and timer unit contents.
func Render(binPath, configPath string, interval time.Duration) (service, timer string) {
	service = fmt.Sprintf(`[Unit]
Description=RFC 2136 dynamic DNS update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s run --config %s

[Install]
WantedBy=multi-user.target
`, quoteArg(binPath), quoteArg(configPath))

	timer = fmt.Sprintf(`[Unit]
Description=Periodic RFC 2136 DNS update

[Timer]
OnBootSec=1min
OnUnitActiveSec=%s
Persistent=true

[Install]
WantedBy=timers.target
`, config.SystemdInterval(interval))
	return service, timer
}

// Apply writes the service and timer units into dir.
func Apply(dir, binPath, configPath string, interval time.Duration) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	service, timer := Render(binPath, configPath, interval)
	if err := os.WriteFile(filepath.Join(dir, serviceName), []byte(service), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, timerName), []byte(timer), 0644)
}

func quoteArg(path string) string {
	if path == "" || strings.ContainsAny(path, " \t") {
		return strconvQuote(path)
	}
	return path
}

func strconvQuote(path string) string {
	return `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
}
