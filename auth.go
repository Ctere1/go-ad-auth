package auth

import (
	ldap "github.com/go-ldap/ldap/v3"
)

// Authenticate checks if the given credentials are valid, or returns an error if one occurred.
// username may be either the sAMAccountName or the userPrincipalName.
func Authenticate(config *Config, username, password string) (bool, error) {
	user, err := config.ExtractUserName(username)
	if err != nil {
		return false, err
	}

	conn, err := config.Connect()
	if err != nil {
		return false, err
	}
	defer conn.Conn.Close()

	return conn.Bind(user, password)
}

// AuthenticateExtended checks if the given credentials are valid, or returns an error if one occurred.
// username may be either the sAMAccountName or the userPrincipalName.
// entry is the *ldap.Entry that holds the DN and any request attributes of the user.
// If groups is non-empty, userGroups will hold which of those groups the user is a member of.
// groups can be a list of groups referenced by DN or cn and the format provided will be the format returned.
func AuthenticateExtended(config *Config, username, password string, attrs, groups []string) (status bool, entry *ldap.Entry, userGroups []string, err error) {
	user, err := config.ExtractUserName(username)
	if err != nil {
		return false, nil, nil, err
	}

	conn, err := config.Connect()
	if err != nil {
		return false, nil, nil, err
	}
	defer conn.Conn.Close()

	//bind
	status, err = conn.Bind(user, password)
	if err != nil {
		return false, nil, nil, err
	}
	if !status {
		return false, nil, nil, nil
	}

	// Determine search attribute
	attr := "userPrincipalName"
	if config.EnforceSamAccountNameSearch {
		attr = "sAMAccountName"
	}

	// Retrieve user attributes
	entry, err = conn.GetAttributes(attr, user, attrs)
	if err != nil {
		return false, nil, nil, err
	}

	if len(groups) > 0 {
		//get all groups
		foundGroups, err := conn.getGroups(entry.DN)
		if err != nil {
			return false, nil, nil, err
		}

		groupMap := make(map[string]struct{}, len(foundGroups))
		for _, userGroup := range foundGroups {
			groupMap[userGroup.DN] = struct{}{}
		}

		for _, group := range groups {
			groupDN, err := conn.GroupDN(group)
			if err != nil {
				return false, nil, nil, err
			}

			if _, exists := groupMap[groupDN]; exists {
				userGroups = append(userGroups, group)
			}
		}
	}

	return status, entry, userGroups, nil
}
