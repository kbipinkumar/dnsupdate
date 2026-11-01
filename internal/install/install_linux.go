//go:build linux

package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Install writes unit files and enables the timer. It must run as root.
func Install(binPath, configPath string, interval time.Duration) error {
	if os.Geteuid() != 0 {
		return errors.New("dnsupdate install must be run as root")
	}
	info, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("binary path is a directory")
	}
	if !filepath.IsAbs(binPath) || !filepath.IsAbs(configPath) {
		return errors.New("binary and config paths must be absolute")
	}
	if err := Apply(UnitDir, binPath, configPath, interval); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", "dnsupdate.timer")
}

// Uninstall disables the timer and removes the unit files.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("dnsupdate uninstall must be run as root")
	}
	_ = systemctl("disable", "--now", "dnsupdate.timer")
	_ = os.Remove(filepath.Join(UnitDir, timerName))
	_ = os.Remove(filepath.Join(UnitDir, serviceName))
	return systemctl("daemon-reload")
}

func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
