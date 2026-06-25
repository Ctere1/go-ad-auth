package auth_test

import (
	auth "github.com/Ctere1/go-ad-auth"
)

func ExampleUpdatePassword() {
	config := &auth.Config{
		Server:   "ldap.example.com",
		Port:     389,
		BaseDN:   "OU=Users,DC=example,DC=com",
		Security: auth.SecurityStartTLS, // Active Directory requires a secure connection to reset passwords
	}

	username := "user"
	password := "pass"
	newPassword := "Super$ecret"

	if err := auth.UpdatePassword(config, username, password, newPassword); err != nil {
		//handle err
	}
}
