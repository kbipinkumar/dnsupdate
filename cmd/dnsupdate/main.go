package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dnsupdate/internal/config"
	"dnsupdate/internal/install"
	"dnsupdate/internal/ipaddr"
	"dnsupdate/internal/setup"
	"dnsupdate/internal/update"
)

var version = "dev"

const usageText = `dnsupdate — RFC 2136 dynamic DNS update

Usage:
  dnsupdate setup [flags]
  dnsupdate run [--dry-run] [--config PATH]
  dnsupdate show [--config PATH]
  dnsupdate install [--bin PATH] [--config PATH]
  dnsupdate uninstall
  dnsupdate version

Default config: /etc/dnsupdate/config.toml
Override with --config or the DNSUPDATE_CONFIG environment variable.

setup writes a mode 0600 config. Prefer the interactive wizard so the TSIG
secret is not stored in shell history. --generate-key mints a random base64
secret and prints it once. run performs one update and is the command
executed by the systemd timer.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
	if err := dispatch(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
		return nil
	case "-v", "--version", "version":
		fmt.Printf("dnsupdate %s\n", version)
		return nil
	case "setup":
		return cmdSetup(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "show":
		return cmdShow(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "config file path")
	server := fs.String("server", "", "DNS server IP")
	port := fs.Int("port", 0, "DNS server port")
	zone := fs.String("zone", "", "DNS zone")
	domain := fs.String("domain", "", "record owner name")
	ttl := fs.Uint("ttl", 0, "record TTL in seconds")
	interval := fs.String("interval", "", "timer interval, for example 5m")
	keyName := fs.String("key-name", "", "TSIG key name")
	keyAlgo := fs.String("key-algorithm", "", "TSIG algorithm: hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512")
	keySecret := fs.String("key-secret", "", "base64 TSIG secret")
	keyFile := fs.String("key-file", "", "BIND TSIG key file; overrides name, algorithm, and secret")
	generateKey := fs.Bool("generate-key", false, "generate a random base64 TSIG secret; printed once after the config is written")
	nonInteractive := fs.Bool("non-interactive", false, "write the config from flags without the form")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: dnsupdate setup [flags]\n\nFlags prefill the wizard. --non-interactive writes the file without a form.\n--generate-key mints a random base64 TSIG secret sized for the key algorithm.\nIn the wizard it starts the confirm at Yes. The secret is printed once after the config is written and is not shown again.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	path := config.PathFrom(*configPath)
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *generateKey && (set["key-secret"] || set["key-file"]) {
		return fmt.Errorf("--generate-key cannot be combined with --key-secret or --key-file")
	}

	cfg := config.Defaults()
	if existing, err := config.Read(path); err == nil {
		cfg = existing
	}
	fields := setup.FromConfig(cfg)
	if set["server"] {
		fields.Server = *server
	}
	if set["port"] {
		fields.Port = strconv.Itoa(*port)
	}
	if set["zone"] {
		fields.Zone = *zone
	}
	if set["domain"] {
		fields.Domain = *domain
	}
	if set["ttl"] {
		fields.TTL = strconv.FormatUint(uint64(*ttl), 10)
	}
	if set["interval"] {
		fields.Interval = *interval
	}
	if set["key-name"] {
		fields.KeyName = *keyName
	}
	if set["key-algorithm"] {
		fields.KeyAlgorithm = *keyAlgo
	}
	if set["key-secret"] {
		fields.KeySecret = *keySecret
	}
	if set["key-file"] {
		fields.KeyFile = *keyFile
	}

	valueSet := *generateKey
	for _, name := range []string{"server", "port", "zone", "domain", "ttl", "interval", "key-name", "key-algorithm", "key-secret", "key-file"} {
		if set[name] {
			valueSet = true
			break
		}
	}
	interactive := !*nonInteractive
	if !isTerminal(os.Stdin) && valueSet {
		interactive = false
	}
	if interactive && !isTerminal(os.Stdin) {
		return fmt.Errorf("setup needs a terminal, or --non-interactive with the required flags")
	}
	var generated string
	if interactive {
		var err error
		generated, err = setup.Wizard(&fields, path, *generateKey)
		if err != nil {
			return err
		}
	} else if *generateKey {
		if strings.TrimSpace(fields.KeyFile) != "" {
			return fmt.Errorf("--generate-key cannot be used with a key file")
		}
		secret, err := config.GenerateSecret(fields.KeyAlgorithm)
		if err != nil {
			return err
		}
		fields.KeySecret = secret
		generated = secret
	}

	parsed, err := setup.Parse(fields)
	if err != nil {
		return err
	}
	if _, err := parsed.Resolve(path); err != nil {
		return err
	}
	if err := config.Save(path, parsed); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)
	if generated != "" {
		fmt.Printf("Generated TSIG secret (copy this to the DNS server; it will not be shown again):\n%s\n", generated)
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "config file path")
	dryRun := fs.Bool("dry-run", false, "query DNS and print the update without sending it")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: dnsupdate run [--dry-run] [--config PATH]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	res, err := loadResolved(*configPath)
	if err != nil {
		return err
	}
	v4, v6, err := ipaddr.Detect(res.Server, res.Port)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return update.Run(ctx, res, update.Local{IPv4: v4, IPv6: v6}, *dryRun, os.Stdout)
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "config file path")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: dnsupdate show [--config PATH]\n\nPrints the config with the TSIG secret redacted.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	path := config.PathFrom(*configPath)
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	text, err := config.Format(cfg.Redacted())
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "config file path")
	bin := fs.String("bin", "/usr/local/bin/dnsupdate", "absolute path to the dnsupdate binary")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: dnsupdate install [--bin PATH] [--config PATH]\n\nInstalls dnsupdate.service and dnsupdate.timer, then enables the timer. Must be run as root on Linux.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	path := config.PathFrom(*configPath)
	res, err := loadResolved(path)
	if err != nil {
		return err
	}
	absConfig, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	absBin, err := filepath.Abs(*bin)
	if err != nil {
		return err
	}
	return install.Install(absBin, absConfig, res.Interval)
}

func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: dnsupdate uninstall\n\nDisables dnsupdate.timer and removes the unit files. Must be run as root on Linux.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return install.Uninstall()
}

func loadResolved(configFlag string) (config.Resolved, error) {
	path := config.PathFrom(configFlag)
	cfg, err := config.Load(path)
	if err != nil {
		return config.Resolved{}, err
	}
	return cfg.Resolve(path)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
