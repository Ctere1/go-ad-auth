package auth

import (
	"sort"
	"strings"
	"testing"
)

func TestPrimaryGroupSIDFilter(t *testing.T) {
	t.Run("rewrites RID for valid SID", func(t *testing.T) {
		sid, err := ParseSID("S-1-5-21-2562418665-3218585558-1813906818-1576")
		if err != nil {
			t.Fatalf("Expected SID parse to succeed: %v", err)
		}

		rawSID, err := sid.MarshalBinary()
		if err != nil {
			t.Fatalf("Expected SID marshal to succeed: %v", err)
		}

		filter, err := primaryGroupSIDFilter(rawSID, 513)
		if err != nil {
			t.Fatalf("Expected filter generation to succeed: %v", err)
		}

		expected, err := ParseSID("S-1-5-21-2562418665-3218585558-1813906818-513")
		if err != nil {
			t.Fatalf("Expected target SID parse to succeed: %v", err)
		}

		if filter != expected.FilterString() {
			t.Fatalf("Expected filter %q but got %q", expected.FilterString(), filter)
		}
	})

	t.Run("rejects malformed SID bytes", func(t *testing.T) {
		_, err := primaryGroupSIDFilter([]byte{1, 1, 0, 0, 0, 0, 0, 5}, 513)
		if err == nil {
			t.Fatal("Expected error for malformed SID bytes but got nil")
		}
		if !strings.Contains(err.Error(), "invalid objectSid") {
			t.Fatalf("Expected invalid objectSid error but got: %v", err)
		}
	})

	t.Run("rejects SID without sub authorities", func(t *testing.T) {
		sid := &SID{
			Revision:            SIDRevision,
			SubAuthorityLength:  0,
			IdentifierAuthority: 5,
		}

		rawSID, err := sid.MarshalBinary()
		if err != nil {
			t.Fatalf("Expected SID marshal to succeed: %v", err)
		}

		_, err = primaryGroupSIDFilter(rawSID, 513)
		if err == nil {
			t.Fatal("Expected error for SID without sub authorities but got nil")
		}
		if !strings.Contains(err.Error(), "missing sub authorities") {
			t.Fatalf("Expected missing sub authorities error but got: %v", err)
		}
	})
}

func dnToCN(dn string) string {
	if splits := strings.Split(dn, ","); len(splits) >= 1 {
		if splits2 := strings.Split(splits[0], "="); len(splits2) >= 2 {
			return splits2[1]
		}
	}

	return ""
}

func TestConnGroupDN(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := newTestConfig(testConfig.Port, testConfig.BaseDN)
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	status, err := conn.Bind(testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Error binding to server:", err)
	}

	if !status {
		t.Fatal("Error binding to server: invalid credentials")
	}

	entry, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"memberOf"})
	if err != nil {
		t.Fatal("Error getting user groups:", err)
	}

	dnGroups := entry.GetAttributeValues("memberOf")

	if len(dnGroups) == 0 {
		t.Skip("BIND_UPN user not member of any groups")
		return
	}

	groupDN, err := conn.GroupDN(dnGroups[0])
	if err != nil {
		t.Error("Expected err to be nil but got:", err)
	}
	if dnGroups[0] != groupDN {
		t.Errorf("Expected returned group (%s) to be equal to the searched group (%s)", groupDN, dnGroups[0])
	}

	cn := dnToCN(dnGroups[0])
	if cn == "" {
		t.Fatal("Error getting group cn: cn not found")
	}

	groupDN, err = conn.GroupDN(cn)
	if err != nil {
		t.Error("Expected err to be nil but got:", err)
	}

	if dnGroups[0] != groupDN {
		t.Errorf(`Expected DN to be "%s" but got "%s"`, dnGroups[0], groupDN)
	}
}

func TestConnObjectGroups(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := newTestConfig(testConfig.Port, testConfig.BaseDN)
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	status, err := conn.Bind(testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Error binding to server:", err)
	}

	if !status {
		t.Fatal("Error binding to server: invalid credentials")
	}

	entry, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"memberOf"})
	if err != nil {
		t.Fatal("Error getting user groups:", err)
	}

	dnGroups := entry.GetAttributeValues("memberOf")

	if len(dnGroups) == 0 {
		t.Skip("BIND_UPN user not member of any groups")
		return
	}

	if _, err = conn.ObjectGroups("objectClass", "false", dnGroups); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("No entries: Expected no entries search error but got:", err)
	}

	userGroups, err := conn.ObjectGroups("userPrincipalName", testConfig.BindUPN, dnGroups)
	if err != nil {
		t.Fatal("Expected err to be nil but got:", err)
	}

	sort.Strings(dnGroups)
	sort.Strings(userGroups)

	if len(dnGroups) != len(userGroups) {
		t.Errorf("Expected returned group count (%d) to be equal to searched group count (%d)", len(userGroups), len(dnGroups))
	}

	for i := range dnGroups {
		if dnGroups[i] != userGroups[i] {
			t.Fatalf("Expected returned group (%s) to be equal to searched group (%s):", userGroups[i], dnGroups[i])
		}
	}

	userGroups, err = conn.ObjectGroups("dn", entry.DN, dnGroups)
	if err != nil {
		t.Fatal("Using DN: Expected err to be nil but got:", err)
	}

	sort.Strings(userGroups)

	if len(dnGroups) != len(userGroups) {
		t.Errorf("Using DN: Expected returned group count (%d) to be equal to searched group count (%d)", len(userGroups), len(dnGroups))
	}

	for i := range dnGroups {
		if dnGroups[i] != userGroups[i] {
			t.Fatalf("Using DN: Expected returned group (%s) to be equal to searched group (%s):", userGroups[i], dnGroups[i])
		}
	}
}

func TestConnObjectPrimaryGroup(t *testing.T) {
	if testConfig.Server == "" {
		t.Skip("ADTEST_SERVER not set")
		return
	}

	if testConfig.BindUPN == "" || testConfig.BindPass == "" {
		t.Skip("ADTEST_BIND_UPN or ADTEST_BIND_PASS not set")
		return
	}

	if testConfig.BaseDN == "" {
		t.Skip("ADTEST_BASEDN not set")
		return
	}

	config := newTestConfig(testConfig.Port, testConfig.BaseDN)
	conn, err := config.Connect()
	if err != nil {
		t.Fatal("Error connecting to server:", err)
	}
	defer conn.Conn.Close()

	status, err := conn.Bind(testConfig.BindUPN, testConfig.BindPass)
	if err != nil {
		t.Fatal("Error binding to server:", err)
	}

	if !status {
		t.Fatal("Error binding to server: invalid credentials")
	}

	entry, err := conn.GetAttributes("userPrincipalName", testConfig.BindUPN, []string{"memberOf"})
	if err != nil {
		t.Fatal("Error getting user groups:", err)
	}

	dnGroups := entry.GetAttributeValues("memberOf")

	if len(dnGroups) == 0 {
		t.Skip("BIND_UPN user not member of any groups")
		return
	}

	if _, err = conn.ObjectPrimaryGroup("objectClass", "false"); !strings.HasSuffix(err.Error(), "no entries returned") {
		t.Error("No entries: Expected no entries search error but got:", err)
	}

	dn, err := conn.ObjectPrimaryGroup("userPrincipalName", testConfig.BindUPN)
	if err != nil {
		t.Fatal("Expected err to be nil but got:", err)
	}

	if dn == "" {
		t.Error("Expected to primary group dn to not be empty")
	}
}
