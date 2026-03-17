package auth

import (
	"crypto/tls"
	"errors"
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
)

// Conn represents an Active Directory connection.
type Conn struct {
	Conn   *ldap.Conn
	Config *Config
}

type startTLSClient interface {
	StartTLS(*tls.Config) error
	Close() error
}

func startTLSAndCloseOnError(conn startTLSClient, config *tls.Config) error {
	err := conn.StartTLS(config)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("connection error: %w", err)
	}

	return nil
}

// Connect returns an open connection to an Active Directory server or an error if one occurred.
func (c *Config) Connect() (*Conn, error) {
	switch c.Security {
	case SecurityNone:
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityTLS:
		conn, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", c.Server, c.Port), ldap.DialWithTLSConfig(&tls.Config{ServerName: c.tlsServerName(), RootCAs: c.RootCAs}))
		if err != nil {
			return nil, fmt.Errorf("connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityStartTLS:
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("connection error: %w", err)
		}
		err = startTLSAndCloseOnError(conn, &tls.Config{ServerName: c.tlsServerName(), RootCAs: c.RootCAs})
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureTLS:
		conn, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", c.Server, c.Port), ldap.DialWithTLSConfig(&tls.Config{ServerName: c.tlsServerName(), InsecureSkipVerify: true}))
		if err != nil {
			return nil, fmt.Errorf("connection error: %w", err)
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureStartTLS:
		conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port))
		if err != nil {
			return nil, fmt.Errorf("connection error: %w", err)
		}
		err = startTLSAndCloseOnError(conn, &tls.Config{ServerName: c.tlsServerName(), InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	default:
		return nil, errors.New("configuration error: invalid SecurityType")
	}
}

// Bind authenticates the connection with the given username and password
// and returns the result or an error if one occurred.
func (c *Conn) Bind(username, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	err := c.Conn.Bind(username, password)
	if err != nil {
		if e, ok := err.(*ldap.Error); ok {
			if e.ResultCode == ldap.LDAPResultInvalidCredentials {
				return false, nil
			}
		}
		return false, fmt.Errorf("Bind error (%s): %w", username, err)
	}

	return true, nil
}
