package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

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

// tlsConfig builds the *tls.Config used for the given security mode. MinVersion is
// pinned to TLS 1.2 (RFC 8996 deprecates TLS 1.0/1.1) regardless of the crypto/tls default.
// For the verifying modes RootCAs is honored; for the insecure modes certificate
// verification is explicitly disabled.
func (c *Config) tlsConfig(insecure bool) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: c.tlsServerName(),
	}
	if insecure {
		cfg.InsecureSkipVerify = true
	} else {
		cfg.RootCAs = c.RootCAs
	}
	return cfg
}

// dialURL dials the given LDAP URL applying the configured dial timeout (if any) and an
// optional TLS config (for ldaps://). After a successful dial the per-operation timeout is
// applied so that subsequent LDAP requests cannot block indefinitely.
func (c *Config) dialURL(addr string, tlsConfig *tls.Config) (*ldap.Conn, error) {
	timeout := c.effectiveTimeout()

	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: timeout})}
	if tlsConfig != nil {
		opts = append(opts, ldap.DialWithTLSConfig(tlsConfig))
	}

	conn, err := ldap.DialURL(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}

	conn.SetTimeout(timeout)
	return conn, nil
}

// Connect returns an open connection to an Active Directory server or an error if one occurred.
func (c *Config) Connect() (*Conn, error) {
	switch c.Security {
	case SecurityNone:
		conn, err := c.dialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port), nil)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityTLS:
		conn, err := c.dialURL(fmt.Sprintf("ldaps://%s:%d", c.Server, c.Port), c.tlsConfig(false))
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityStartTLS:
		conn, err := c.dialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port), nil)
		if err != nil {
			return nil, err
		}
		err = startTLSAndCloseOnError(conn, c.tlsConfig(false))
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureTLS:
		conn, err := c.dialURL(fmt.Sprintf("ldaps://%s:%d", c.Server, c.Port), c.tlsConfig(true))
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: conn, Config: c}, nil
	case SecurityInsecureStartTLS:
		conn, err := c.dialURL(fmt.Sprintf("ldap://%s:%d", c.Server, c.Port), nil)
		if err != nil {
			return nil, err
		}
		err = startTLSAndCloseOnError(conn, c.tlsConfig(true))
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
