package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// SecurityType specifies the type of security to use when connecting to an Active Directory Server.
type SecurityType int

// Security will default to SecurityNone if not given.
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
	EnforceSamAccountNameSearch bool           // If true, forces searches to use sAMAccountName instead of userPrincipalName.
	LegacyDomainName            string         // Specifies the domain to use for legacy (Pre-Windows 2000) logins in DOMAIN\username format.
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
	if _, err := mail.ParseAddress(username); err == nil {
		return username, nil
	}

	domain, err := c.Domain()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s@%s", username, domain), nil
}

// SamAccountName formats the given username into the "DOMAIN\username" format, adhering to the sAMAccountName standard.
// If LegacyDomainName is set, it overrides the extracted domain from the input username.
//
// Parameters:
//   - username (string): The input username, which should be in UPN format ("username@domain.com").
//
// Returns:
//   - formattedUsername (string): The username formatted as "DOMAIN\username". If LegacyDomainName is set, this value will be "LegacyDomainName\username". Otherwise, the extracted domain from the input username is used, resulting in "ExtractedDomain\username".
//   - extractedUsername (string): The username part without the domain (e.g., "username"). This is useful for attribute-based LDAP lookups.
//   - err (error): Returns an error if the username format is invalid or if the domain extraction fails.
func (c *Config) SamAccountName(username string) (string, string, error) {
	// Split username into user and domain parts
	parts := strings.SplitN(username, "@", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid username format: %s", username)
	}

	user := parts[0]
	domainParts := strings.Split(parts[1], ".")
	if len(domainParts) < 2 {
		return "", "", fmt.Errorf("invalid domain format in username: %s", username)
	}

	// Extract the first part of the domain (e.g., "test" from "test.com")
	domain := domainParts[0]

	// If LegacyDomainName is defined, use it instead of the extracted domain
	if c.LegacyDomainName != "" {
		domain = c.LegacyDomainName
	}

	// Return "DOMAIN\username" format
	return fmt.Sprintf("%s\\%s", domain, user), user, nil
}

// ExtractUserName determines the appropriate format for the given username based on the configuration settings.
// If EnforceSamAccountNameSearch is enabled, it returns the sAMAccountName format in "DOMAIN\username" style.
// Otherwise, it defaults to the userPrincipalName (UPN) format ("username@domain.com").
//
// Parameters:
//   - username: The input username which can be in UPN format ("username@domain.com") or a simple username ("username").
//
// Returns:
//   - formattedUsername (string): The fully formatted username based on the configuration settings. This will be either: "DOMAIN\username" if EnforceSamAccountNameSearch is enabled. "username@domain.com" (UPN format) otherwise.
//   - extractedUsername (string): The extracted username without the domain part. This is useful for attribute-based LDAP lookups.
//   - err (error): Returns an error if the username format is invalid or if domain resolution fails.
func (c *Config) ExtractUserName(username string) (string, string, error) {
	// Check if the username is an email address and return it as is
	if _, err := mail.ParseAddress(username); err == nil {
		return username, strings.Split(username, "@")[0], nil
	}

	// If EnforceSamAccountNameSearch is marked as true, then we will always search for the sAMAccountName
	if c.EnforceSamAccountNameSearch {
		return c.SamAccountName(username)
	}

	upn, err := c.UPN(username)
	if err != nil {
		return "", "", err
	}

	// return the username without the domain
	user := strings.Split(upn, "@")[0]
	return upn, user, nil
}
