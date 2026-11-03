package config

import (
	"encoding/base64"
	"testing"
)

func TestGenerateSecret(t *testing.T) {
	cases := []struct {
		algo string
		n    int
	}{
		{"hmac-sha1", 20},
		{"hmac-sha224", 28},
		{"hmac-sha256", 32},
		{"HMAC-SHA384.", 48},
		{"hmac-sha512", 64},
	}
	for _, tc := range cases {
		t.Run(tc.algo, func(t *testing.T) {
			a, err := GenerateSecret(tc.algo)
			if err != nil {
				t.Fatal(err)
			}
			b, err := GenerateSecret(tc.algo)
			if err != nil {
				t.Fatal(err)
			}
			if a == b {
				t.Fatal("two generated secrets were identical")
			}
			raw, err := base64.StdEncoding.DecodeString(a)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != tc.n {
				t.Fatalf("decoded length = %d, want %d", len(raw), tc.n)
			}
		})
	}
}

func TestGenerateSecretRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := GenerateSecret("hmac-md5"); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}
