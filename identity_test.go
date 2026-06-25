package auth

import "testing"

func TestExtractSAMAccountName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain login", "jdoe", "jdoe"},
		{"upn form", "jdoe@example.com", "jdoe"},
		{"down-level form", `EXAMPLE\jdoe`, "jdoe"},
		{"trims whitespace", "  jdoe  ", "jdoe"},
		{"upn with subdomain", "jdoe@corp.example.com", "jdoe"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSAMAccountName(tt.in); got != tt.want {
				t.Fatalf("extractSAMAccountName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDownLevelLogonName(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		in     string
		want   string
	}{
		{
			"derives netbios from upn first label",
			&Config{BaseDN: "dc=example,dc=com"},
			"jdoe@corp.example.com",
			`corp\jdoe`,
		},
		{
			"derives netbios from basedn for plain login",
			&Config{BaseDN: "dc=example,dc=com"},
			"jdoe",
			`example\jdoe`,
		},
		{
			"legacy domain name overrides derivation",
			&Config{BaseDN: "dc=example,dc=com", LegacyDomainName: "EXAMPLE"},
			"jdoe@corp.example.com",
			`EXAMPLE\jdoe`,
		},
		{
			"keeps explicit down-level domain",
			&Config{BaseDN: "dc=example,dc=com"},
			`CONTOSO\jdoe`,
			`CONTOSO\jdoe`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.config.downLevelLogonName(tt.in, extractSAMAccountName(tt.in))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("downLevelLogonName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestResolveDefaultMode(t *testing.T) {
	c := &Config{BaseDN: "dc=example,dc=com"}

	id, err := c.Resolve("jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.BindName != "jdoe@example.com" {
		t.Errorf("BindName = %q, want jdoe@example.com", id.BindName)
	}
	if id.SearchAttribute != attrUserPrincipalName {
		t.Errorf("SearchAttribute = %q, want %q", id.SearchAttribute, attrUserPrincipalName)
	}
	if id.SearchValue != "jdoe@example.com" {
		t.Errorf("SearchValue = %q, want jdoe@example.com", id.SearchValue)
	}
}

func TestResolveEnforceSamAccountName(t *testing.T) {
	// Across every input form the search MUST use the bare sAMAccountName, never the down-level
	// "DOMAIN\user" string — issuing (sAMAccountName=DOMAIN\user) never matches in AD and was
	// the original bug this design fixes. The bind, by contrast, uses the down-level name.
	tests := []struct {
		name       string
		config     *Config
		input      string
		wantBind   string
		wantSearch string
	}{
		{
			"upn input",
			&Config{BaseDN: "dc=example,dc=com", EnforceSamAccountNameSearch: true},
			"jdoe@example.com",
			`example\jdoe`,
			"jdoe",
		},
		{
			"plain input derives netbios from basedn",
			&Config{BaseDN: "dc=example,dc=com", EnforceSamAccountNameSearch: true},
			"jdoe",
			`example\jdoe`,
			"jdoe",
		},
		{
			"down-level input keeps its domain",
			&Config{BaseDN: "dc=example,dc=com", EnforceSamAccountNameSearch: true},
			`CONTOSO\jdoe`,
			`CONTOSO\jdoe`,
			"jdoe",
		},
		{
			"legacy domain overrides derivation",
			&Config{BaseDN: "dc=example,dc=com", EnforceSamAccountNameSearch: true, LegacyDomainName: "EXAMPLE"},
			"jdoe@corp.example.com",
			`EXAMPLE\jdoe`,
			"jdoe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := tt.config.Resolve(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.SearchAttribute != attrSAMAccountName {
				t.Errorf("SearchAttribute = %q, want %q", id.SearchAttribute, attrSAMAccountName)
			}
			if id.SearchValue != tt.wantSearch {
				t.Errorf("SearchValue = %q, want bare sAMAccountName %q", id.SearchValue, tt.wantSearch)
			}
			if id.BindName != tt.wantBind {
				t.Errorf("BindName = %q, want %q", id.BindName, tt.wantBind)
			}
		})
	}
}

func TestResolveRejectsEmptyUsername(t *testing.T) {
	c := &Config{BaseDN: "dc=example,dc=com"}
	if _, err := c.Resolve("   "); err == nil {
		t.Fatal("expected error for empty username but got nil")
	}
}

func TestResolvePropagatesDomainError(t *testing.T) {
	// A misconfigured BaseDN must surface as an error in both modes when the domain has to be
	// derived (plain login), rather than producing a malformed bind/search identity.
	tests := []struct {
		name   string
		config *Config
	}{
		{"default mode", &Config{BaseDN: "Bad OU"}},
		{"enforce sam mode", &Config{BaseDN: "Bad OU", EnforceSamAccountNameSearch: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.config.Resolve("jdoe"); err == nil {
				t.Fatal("expected error for invalid BaseDN but got nil")
			}
		})
	}
}
