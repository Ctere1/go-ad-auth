package auth

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"
)

type stubStartTLSClient struct {
	startTLSErr error
	startTLSHit bool
	closeHit    bool
}

func (s *stubStartTLSClient) StartTLS(*tls.Config) error {
	s.startTLSHit = true
	return s.startTLSErr
}

func (s *stubStartTLSClient) Close() error {
	s.closeHit = true
	return nil
}

func TestConfigConnect(t *testing.T) {
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityNone}).Connect(); err == nil {
		t.Error("SecurityNone: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityTLS}).Connect(); err == nil {
		t.Error("SecurityTLS: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityStartTLS}).Connect(); err == nil {
		t.Error("SecurityStartTLS: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityInsecureTLS}).Connect(); err == nil {
		t.Error("SecurityInsecureTLS: Expected connect error but got nil")
	}
	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityInsecureStartTLS}).Connect(); err == nil {
		t.Error("SecurityInsecureStartTLS: Expected connect error but got nil")
	}

	if _, err := (&Config{Server: "127.0.0.1", Port: 1, Security: SecurityType(100)}).Connect(); err == nil {
		t.Error("Invalid Security: Expected configuration error but got nil")
	}

	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.Port, Security: SecurityNone}).Connect(); err != nil {
		t.Error("SecurityNone: Expected connect error to be nil but got:", err)
	}
	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.TLSPort, Security: SecurityTLS, RootCAs: testConfig.RootCAs, TLSServerName: testConfig.TLSServerName}).Connect(); err != nil {
		t.Error("SecurityTLS: Expected connect error to be nil but got:", err)
	}
	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.Port, Security: SecurityStartTLS, RootCAs: testConfig.RootCAs, TLSServerName: testConfig.TLSServerName}).Connect(); err != nil {
		t.Error("SecurityStartTLS: Expected connect error to be nil but got:", err)
	}
	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.TLSPort, Security: SecurityInsecureTLS}).Connect(); err != nil {
		t.Error("SecurityInsecureTLS: Expected connect error to be nil but got:", err)
	}
	if _, err := (&Config{Server: testConfig.Server, Port: testConfig.Port, Security: SecurityInsecureStartTLS}).Connect(); err != nil {
		t.Error("SecurityInsecureStartTLS: Expected connect error to be nil but got:", err)
	}
}

func TestStartTLSAndCloseOnError(t *testing.T) {
	t.Run("closes connection on StartTLS failure", func(t *testing.T) {
		client := &stubStartTLSClient{startTLSErr: errors.New("tls failed")}

		err := startTLSAndCloseOnError(client, &tls.Config{ServerName: "ldap.example.com"})
		if err == nil {
			t.Fatal("Expected error but got nil")
		}
		if !strings.Contains(err.Error(), "connection error") {
			t.Fatalf("Expected wrapped connection error but got: %v", err)
		}
		if !client.startTLSHit {
			t.Fatal("Expected StartTLS to be called")
		}
		if !client.closeHit {
			t.Fatal("Expected Close to be called after StartTLS failure")
		}
	})

	t.Run("does not close connection on StartTLS success", func(t *testing.T) {
		client := &stubStartTLSClient{}

		err := startTLSAndCloseOnError(client, &tls.Config{ServerName: "ldap.example.com"})
		if err != nil {
			t.Fatalf("Expected nil error but got: %v", err)
		}
		if !client.startTLSHit {
			t.Fatal("Expected StartTLS to be called")
		}
		if client.closeHit {
			t.Fatal("Expected Close not to be called after successful StartTLS")
		}
	})
}

func TestConnBind(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	config := newTestConfig(testConfig.Port, "")
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	if status, _ := conn.Bind("test", ""); status {
		t.Error("Empty password: Expected authentication status to be false")
	}

	if status, _ := conn.Bind("go-ad-auth", "invalid_password"); status {
		t.Error("Invalid credentials: Expected authentication status to be false")
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if status, _ := conn.Bind(testConfig.BindUPN, testConfig.BindPass); !status {
		t.Error("Valid credentials: Expected authentication status to be true")
	}
}
