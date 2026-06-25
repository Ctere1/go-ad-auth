package auth

import (
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
)

// Search returns the entries for the given search criteria or an error if one occurred.
func (c *Conn) Search(filter string, attrs []string, sizeLimit int) ([]*ldap.Entry, error) {
	search := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		sizeLimit,
		0,
		false,
		filter,
		attrs,
		nil,
	)
	result, err := c.Conn.Search(search)
	if err != nil {
		return nil, fmt.Errorf(`search error "%s": %w`, filter, err)
	}

	return result.Entries, nil
}

// SearchOne returns the single entry for the given search criteria or an error if one occurred.
// An error is returned if exactly one entry is not returned.
func (c *Conn) SearchOne(filter string, attrs []string) (*ldap.Entry, error) {
	search := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		1,
		0,
		false,
		filter,
		attrs,
		nil,
	)

	result, err := c.Conn.Search(search)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultSizeLimitExceeded {
				return nil, fmt.Errorf(`search error "%s": more than one entries returned`, filter)
			}
		}

		return nil, fmt.Errorf(`search error "%s": %w`, filter, err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf(`search error "%s": no entries returned`, filter)
	}

	return result.Entries[0], nil
}

// GetDN returns the DN for the object with the given attribute value or an error if one occurred.
// attr and value are sanitized.
func (c *Conn) GetDN(attr, value string) (string, error) {
	entry, err := c.SearchOne(fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(attr), ldap.EscapeFilter(value)), []string{""})
	if err != nil {
		return "", err
	}

	return entry.DN, nil
}

// GetAttributes returns the *ldap.Entry with the given attributes for the object with the given attribute value or an error if one occurred.
// attr and value are sanitized.
func (c *Conn) GetAttributes(attr, value string, attrs []string) (*ldap.Entry, error) {
	return c.SearchOne(fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(attr), ldap.EscapeFilter(value)), attrs)
}

// adPageSize is the page size used for paged group-membership searches. Active Directory's
// default MaxPageSize is 1000; using the Simple Paged Results control (RFC 2696) lets us
// retrieve the complete membership set across multiple pages instead of being silently
// truncated at the first 1000 entries.
const adPageSize = 1000

func (c *Conn) getGroups(dn string) ([]*ldap.Entry, error) {
	filter := fmt.Sprintf("(member:%s:=%s)", LDAPMatchingRuleInChain, ldap.EscapeFilter(dn))
	search := ldap.NewSearchRequest(
		c.Config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		0, // no client-side size limit; paging retrieves the full result set
		0,
		false,
		filter,
		[]string{""},
		nil,
	)

	result, err := c.Conn.SearchWithPaging(search, adPageSize)
	if err != nil {
		return nil, fmt.Errorf(`search error "%s": %w`, filter, err)
	}

	return result.Entries, nil
}
