package auth

import (
	"testing"
	"time"
)

func TestConfigDomain(t *testing.T) {
	tests := []string{
		"dc=example,dc=com",
		"ou=test,dc=example,dc=com",
		"dc=example, dc=com",
		"DC=example,DC=com",
		"OU=test,dc=example,DC=com",
	}
	for _, test := range tests {
		if domain, err := (&Config{BaseDN: test}).Domain(); domain != "example.com" {
			if err != nil {
				t.Error("Failed Test:", test, "\n\tError:", err)
			} else {
				t.Error("Failed Test:", test, "\n\tOutput:", domain, "Expected: example.com")
			}
		}
	}
	errorTests := []string{
		"",
		"com",
		"ou=test",
		"OU=test",
	}
	for _, test := range errorTests {
		if _, err := (&Config{BaseDN: test}).Domain(); err == nil {
			t.Error("Failed Test:", test, "\n\tError: err not nil")
		}
	}
}

func TestConfigUPN(t *testing.T) {
	const baseDN = "dc=example,dc=com"

	tests := []struct {
		name    string
		baseDN  string
		input   string
		want    string
		wantErr bool
	}{
		{"plain username gets domain appended", baseDN, "example.user", "example.user@example.com", false},
		{"already a upn is returned unchanged", baseDN, "example.user@example.com", "example.user@example.com", false},
		{"foreign upn suffix is preserved", baseDN, "example.user@other.com", "example.user@other.com", false},
		{"surrounding whitespace is trimmed", baseDN, "  example.user  ", "example.user@example.com", false},
		{"multi-label basedn resolves full domain", "ou=test,dc=corp,dc=example,dc=com", "example.user", "example.user@corp.example.com", false},
		{"display-name form is not trusted as a upn", baseDN, "evil <a@b.com>", "evil <a@b.com>@example.com", false},
		{"invalid basedn for plain user errors", "Bad OU", "example.user", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&Config{BaseDN: tt.baseDN}).UPN(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("UPN(%q): expected error, got %q", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("UPN(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("UPN(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestConfigEffectiveTimeout(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero falls back to default", 0, DefaultTimeout},
		{"negative falls back to default", -time.Second, DefaultTimeout},
		{"explicit value is honored", 5 * time.Second, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&Config{Timeout: tt.in}).effectiveTimeout(); got != tt.want {
				t.Fatalf("effectiveTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
