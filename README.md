[![Go Report Card](https://goreportcard.com/badge/github.com/Ctere1/go-ad-auth)](https://goreportcard.com/report/github.com/Ctere1/go-ad-auth) [![pkg.go.dev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/Ctere1/go-ad-auth)

# About

This is a fork of the [korylprince/go-ad-auth](https://github.com/korylprince/go-ad-auth) project.  

`go-ad-auth` is a simple wrapper around the great [ldap](https://github.com/go-ldap/ldap) library to help with Active Directory authentication.

# Installing

Using Go Modules:

`go get github.com/Ctere1/go-ad-auth`

**Dependencies:**

* [github.com/go-ldap/ldap](https://github.com/go-ldap/ldap)
* [golang.org/x/text/encoding/unicode](https://pkg.go.dev/golang.org/x/text/encoding/unicode)


# Usage

Example:

```go
config := &auth.Config{
  	Server:                      "ldap.example.com",
	Port:                        389,
	BaseDN:                      "OU=Users,DC=example,DC=com",
	Security:                    auth.SecurityStartTLS,
	EnforceSamAccountNameSearch: false,
	LegacyDomainName:            "example.com",
}

username := "user"
password := "pass"

status, err := auth.Authenticate(config, username, password)

if err != nil {
    //handle err
    return
}

if !status {
    //handle failed authentication
    return
}
```

See more advanced examples on [go.dev](https://pkg.go.dev/github.com/Ctere1/go-ad-auth?tab=doc#pkg-examples).

# Testing

`go test -v`

Most tests will be skipped unless you supply the following environment variables to connect to an Active Directory server:

| Name                 | Description                                                                                           |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| ADTEST_SERVER        | Hostname or IP Address of an Active Directory server                                                  |
| ADTEST_PORT          | Port to use - defaults to 389                                                                         |
| ADTEST_BIND_UPN      | userPrincipalName (user@domain.tld) of admin user                                                     |
| ADTEST_BIND_PASS     | Password of admin user                                                                                |
| ADTEST_BIND_SECURITY | `NONE` \|\| `TLS` \|\| `STARTTLS` \|\| `INSECURETLS` \|\| `INSECURESTARTTLS` - defaults to `STARTTLS` |
| ADTEST_BASEDN        | LDAP Base DN - for testing the root DN is recommended, e.g. `DC=example,DC=com`                       |
| ADTEST_PASSWORD_UPN  | userPrincipalName of a test user that will be used to test password changing functions                |

# Nested Groups

[`AuthenticateExtended`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth?tab=doc#AuthenticateExtended) and [`Conn.ObjectGroups`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth?tab=doc#Conn.ObjectGroups) will automatically search for nested groups. For example, if `User A` is a member of `Group A`, and `Group A` is a member of `Group B`, using `Conn.ObjectGroups` on `User A` will return both `Group A` and `Group B`.

# Security

[SQL Injection](https://en.wikipedia.org/wiki/SQL_injection) is a well known attack vector, and most SQL libraries provide mitigations such as [prepared statements](https://en.wikipedia.org/wiki/Prepared_statement). Similarly, [LDAP Injection](https://www.owasp.org/index.php/Testing_for_LDAP_Injection_\(OTG-INPVAL-006\)), while not seen often in the wild, is something we should be concerned with.

This library sanitizes inputs (with [`ldap.EscapeFilter`](https://pkg.go.dev/github.com/go-ldap/ldap/v3?tab=doc#EscapeFilter)) that are used to create LDAP filters in library functions, namely [`GetDN`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth#Conn.GetDN) and [`GetAttributes`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth#Conn.GetAttributes). This means high level functions in this library are protected against malicious inputs. If you use [`Search`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth#Conn.Search) or [`SearchOne`](https://pkg.go.dev/github.com/Ctere1/go-ad-auth#Conn.SearchOne), take care to sanitize any untrusted inputs you use in your LDAP filter.
