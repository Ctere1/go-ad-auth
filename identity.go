package auth

import (
	"fmt"
	"strings"
)

// LDAP attribute names used to locate a user entry.
const (
	attrUserPrincipalName = "userPrincipalName"
	attrSAMAccountName    = "sAMAccountName"
)

// Identity holds the resolved representations of a user-supplied username. Both the bind
// identity and the search predicate are derived from a single source of truth (Config.Resolve),
// so they can never diverge — which is what previously allowed a sAMAccountName search to be
// issued with a down-level "DOMAIN\user" value that an Active Directory server never matches.
type Identity struct {
	// BindName is the identity passed to an LDAP simple bind (RFC 4513): a userPrincipalName
	// ("user@domain") or a down-level logon name ("NetBIOSDomain\sAMAccountName").
	BindName string
	// SearchAttribute is the attribute used to locate the entry: attrUserPrincipalName or
	// attrSAMAccountName.
	SearchAttribute string
	// SearchValue is the raw, unescaped value SearchAttribute must equal. Callers are
	// responsible for escaping it (e.g. via ldap.EscapeFilter) before use in a filter.
	SearchValue string
}

// Resolve maps a user-supplied username onto the representations required to bind and to locate
// the corresponding directory entry.
//
//   - Default mode binds and searches by userPrincipalName.
//   - EnforceSamAccountNameSearch binds with the down-level logon name ("DOMAIN\sam") and
//     searches by the bare sAMAccountName, per MS-ADTS — the sAMAccountName attribute holds the
//     login name only, never the "DOMAIN\" prefix.
func (c *Config) Resolve(username string) (Identity, error) {
	sam := extractSAMAccountName(username)
	if sam == "" {
		return Identity{}, fmt.Errorf("invalid username: %q", username)
	}

	if !c.EnforceSamAccountNameSearch {
		upn, err := c.UPN(username)
		if err != nil {
			return Identity{}, err
		}
		return Identity{
			BindName:        upn,
			SearchAttribute: attrUserPrincipalName,
			SearchValue:     upn,
		}, nil
	}

	bindName, err := c.downLevelLogonName(username, sam)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		BindName:        bindName,
		SearchAttribute: attrSAMAccountName,
		SearchValue:     sam,
	}, nil
}

// extractSAMAccountName returns the bare sAMAccountName (the login name without any domain)
// from a user-supplied identifier. It accepts the userPrincipalName form ("user@domain"), the
// down-level form ("DOMAIN\user"), and a plain login name ("user"). Per MS-ADTS a sAMAccountName
// contains neither "@" nor "\", so those separators unambiguously delimit the domain portion.
func extractSAMAccountName(username string) string {
	s := strings.TrimSpace(username)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[:i]
	}
	if i := strings.LastIndex(s, `\`); i >= 0 {
		return s[i+1:]
	}
	return s
}

// downLevelLogonName builds the down-level logon name ("NetBIOSDomain\sAMAccountName") used for
// a simple bind when EnforceSamAccountNameSearch is set. The NetBIOS domain is taken, in order
// of precedence, from LegacyDomainName, an explicit "DOMAIN\" prefix in the input, or the first
// label of the resolved UPN domain. The last is a best-effort fallback: the NetBIOS name is not
// guaranteed to equal the first DNS label, so LegacyDomainName should be set when they differ.
func (c *Config) downLevelLogonName(username, sam string) (string, error) {
	netbios := c.LegacyDomainName
	if netbios == "" {
		if prefix, _, isDownLevel := strings.Cut(strings.TrimSpace(username), `\`); isDownLevel {
			netbios = prefix
		} else {
			upn, err := c.UPN(username)
			if err != nil {
				return "", err
			}
			domain := upn[strings.LastIndex(upn, "@")+1:]
			netbios, _, _ = strings.Cut(domain, ".")
		}
	}
	if netbios == "" {
		return "", fmt.Errorf("configuration error: unable to determine NetBIOS domain for %q", username)
	}
	return netbios + `\` + sam, nil
}
