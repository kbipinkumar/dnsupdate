//go:build !linux

package install

import (
	"errors"
	"time"
)

// Install is only available on Linux.
func Install(binPath, configPath string, interval time.Duration) error {
	return errors.New("dnsupdate install is only supported on linux")
}

// Uninstall is only available on Linux.
func Uninstall() error {
	return errors.New("dnsupdate uninstall is only supported on linux")
}
