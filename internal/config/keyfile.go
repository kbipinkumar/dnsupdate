package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

var (
	keyNameRE = regexp.MustCompile(`(?i)key\s+"([^"]+)"`)
	keyAlgoRE = regexp.MustCompile(`(?i)algorithm\s+"?([A-Za-z0-9.-]+)"?\s*;`)
	keySecRE  = regexp.MustCompile(`(?is)secret\s+"([^"]+)"\s*;`)
)

// ParseBINDKey reads a BIND key statement.
func ParseBINDKey(data string) (name, algorithm, secret string, err error) {
	nameMatch := keyNameRE.FindStringSubmatch(data)
	algoMatch := keyAlgoRE.FindStringSubmatch(data)
	secMatch := keySecRE.FindStringSubmatch(data)
	if nameMatch == nil || algoMatch == nil || secMatch == nil {
		return "", "", "", fmt.Errorf("expected a BIND key statement with algorithm and secret")
	}
	name = strings.TrimSpace(nameMatch[1])
	algorithm = strings.Trim(strings.TrimSpace(algoMatch[1]), `"`)
	secret = stripSpace(secMatch[1])
	if name == "" || algorithm == "" || secret == "" {
		return "", "", "", fmt.Errorf("expected a BIND key statement with algorithm and secret")
	}
	if _, err := decodeSecret(secret); err != nil {
		return "", "", "", fmt.Errorf("secret is not base64")
	}
	return name, algorithm, secret, nil
}

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

func decodeSecret(secret string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(stripSpace(secret))
}

// GenerateSecret returns a new base64 TSIG secret sized to the HMAC output
// of algorithm (the same lengths BIND tsig-keygen uses).
func GenerateSecret(algorithm string) (string, error) {
	norm, err := NormalizeAlgorithm(algorithm)
	if err != nil {
		return "", err
	}
	n, err := secretLen(norm)
	if err != nil {
		return "", err
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate key secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func secretLen(algorithm string) (int, error) {
	switch algorithm {
	case dns.HmacSHA1:
		return 20, nil
	case dns.HmacSHA224:
		return 28, nil
	case dns.HmacSHA256:
		return 32, nil
	case dns.HmacSHA384:
		return 48, nil
	case dns.HmacSHA512:
		return 64, nil
	default:
		return 0, fmt.Errorf("unsupported key algorithm %q", strings.TrimSuffix(algorithm, "."))
	}
}
