package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const LDAPMatchingRuleInChain = "1.2.840.113556.1.4.1941"

// GroupDN returns the DN of the group with the given cn or an error if one occurred.
func (c *Conn) GroupDN(group string) (string, error) {
	if strings.HasSuffix(group, c.Config.BaseDN) {
		return group, nil
	}

	return c.GetDN("cn", group)
}

// ObjectGroups returns which of the given groups (referenced by DN) the object with the given attribute value is in,
// if any, or an error if one occurred.
// Setting attr to "dn" and value to the DN of an object will avoid an extra LDAP search to get the object's DN.
func (c *Conn) ObjectGroups(attr, value string, groups []string) ([]string, error) {
	dn := value
	if attr != "dn" {
		entry, err := c.GetAttributes(attr, value, []string{""})
		if err != nil {
			return nil, err
		}
		dn = entry.DN
	}

	objectGroups, err := c.getGroups(dn)
	if err != nil {
		return nil, err
	}

	// Create a set of the groups to check against
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	// Check which of the groups the object is in
	var matchedGroups []string
	for _, objectGroup := range objectGroups {
		if _, exists := groupSet[objectGroup.DN]; exists {
			matchedGroups = append(matchedGroups, objectGroup.DN)
		}
	}

	return matchedGroups, nil
}

// ObjectPrimaryGroup returns the DN of the primary group of the object with the given attribute value
// or an error if one occurred. Not all LDAP objects have a primary group.
func (c *Conn) ObjectPrimaryGroup(attr, value string) (string, error) {
	entry, err := c.GetAttributes(attr, value, []string{"objectSid", "primaryGroupID"})
	if err != nil {
		return "", err
	}

	gidStr := entry.GetAttributeValue("primaryGroupID")
	if gidStr == "" {
		return "", errors.New("search error: primaryGroupID not found")
	}

	gid, err := strconv.Atoi(entry.GetAttributeValue("primaryGroupID"))
	if err != nil {
		return "", fmt.Errorf(`parse error: invalid primaryGroupID ("%s"): %w`, gidStr, err)
	}

	encoded, err := primaryGroupSIDFilter(entry.GetRawAttributeValue("objectSid"), uint32(gid))
	if err != nil {
		return "", err
	}

	entry, err = c.SearchOne(fmt.Sprintf("(objectSid=%s)", encoded), nil)
	if err != nil {
		return "", fmt.Errorf("search error: primary group not found: %w", err)
	}

	return entry.DN, nil
}

func primaryGroupSIDFilter(rawSID []byte, gid uint32) (string, error) {
	var sid SID
	if err := sid.UnmarshalBinary(rawSID); err != nil {
		return "", fmt.Errorf("search error: invalid objectSid: %w", err)
	}

	if len(sid.SubAuthoritys) == 0 {
		return "", errors.New("search error: invalid objectSid: missing sub authorities")
	}

	sid.SubAuthoritys[len(sid.SubAuthoritys)-1] = gid
	return sid.FilterString(), nil
}
