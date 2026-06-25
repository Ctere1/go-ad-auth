package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// DefaultTimeout is the dial/operation timeout applied when Config.Timeout is not set (<= 0).
// It bounds both the TCP dial and subsequent LDAP operations so a slow or unreachable
// directory server cannot block the calling goroutine indefinitely.
const DefaultTimeout = 60 * time.Second

// SecurityType specifies the type of security to use when connecting to an Active Directory Server.
type SecurityType int

// Security defaults to SecurityNone if not set, which means plaintext LDAP.
// Callers should explicitly choose a secure mode such as SecurityStartTLS or SecurityTLS.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
	SecurityInsecureTLS
	SecurityInsecureStartTLS
)

// Config contains settings for connecting to an Active Directory server.
type Config struct {
	Server                      string         // Server specifies the hostname of the Active Directory server.
	Port                        int            // Port specifies the port to connect to on the server.
	BaseDN                      string         // BaseDN specifies the base distinguished name to use for searches.
	Security                    SecurityType   // Security specifies the type of security to use when connecting to the server.
	RootCAs                     *x509.CertPool // RootCAs specifies the set of root certificate authorities to use when verifying server certificates.
	TLSServerName               string         // TLSServerName optionally overrides the hostname used for TLS certificate verification.
	EnforceSamAccountNameSearch bool           // If true, forces searches to use sAMAccountName instead of userPrincipalName.
	LegacyDomainName            string         // Specifies the domain to use for legacy (Pre-Windows 2000) logins in DOMAIN\username format.
	Timeout                     time.Duration  // Timeout optionally bounds the dial and per-operation duration. When <= 0, DefaultTimeout is used.
}

// effectiveTimeout returns the configured Timeout, falling back to DefaultTimeout when unset.
func (c *Config) effectiveTimeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *Config) tlsServerName() string {
	if c.TLSServerName != "" {
		return c.TLSServerName
	}

	return c.Server
}

// Domain returns the domain derived from BaseDN or an error if misconfigured.
func (c *Config) Domain() (string, error) {
	domain := ""
	for _, v := range strings.Split(strings.ToLower(c.BaseDN), ",") {
		if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "dc=") {
			domain = domain + "." + trimmed[3:]
		}
	}
	if len(domain) <= 1 {
		return "", errors.New("configuration error: invalid BaseDN")
	}
	return domain[1:], nil
}

// UPN constructs and returns the userPrincipalName (UPN) for the provided username.
// If the username is already in UPN format, it is returned as is or an error if misconfigured.
func (c *Config) UPN(username string) (string, error) {
	// A UPN is an MS-ADTS identifier (user@domain), not an RFC 5322 mailbox. Only treat the
	// input as an already-formed UPN when it contains an "@" and parses to an address whose
	// canonical form equals the input. This rejects display-name/angle-bracket forms such as
	// `evil <a@b.com>`, which mail.ParseAddress accepts but which must not be passed through
	// unchanged as a bind name.
	trimmed := strings.TrimSpace(username)
	if strings.Contains(trimmed, "@") {
		if addr, err := mail.ParseAddress(trimmed); err == nil && addr.Name == "" && addr.Address == trimmed {
			return trimmed, nil
		}
	}

	domain, err := c.Domain()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s@%s", trimmed, domain), nil
}
