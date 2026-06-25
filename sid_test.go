package auth

import (
	"bytes"
	"testing"
)

var ErrSIDTests = []string{
	"1-5-21-50",                 // no "S-"
	"S-2-5-21-50",               // revision 2
	"S-1-562949953421312-21-50", // overflow identifier authority
	"S-1-5-8589934592-50",       // overflow sub authority
}

var ErrSIDBinaryTests = [][]byte{
	{2, 0, 0, 0, 0, 0, 0, 5},                         // revision 2
	{1, 1, 5},                                        // malformed header
	{1, 1, 0, 0, 0, 0, 0, 5, 1, 2},                   // malformed length
	{1, 1, 0, 0, 0, 0, 0, 5},                         // mismatch sub authority length (1 != 0)
	{1, 1, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8}, // mismatch sub authority length (1 != 2)
}

func TestSID(t *testing.T) {
	// taken from https://ldapwiki.com/wiki/ObjectSID
	start := "S-1-5-21-2562418665-3218585558-1813906818-1576"
	startbin := []byte{1, 5, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0, 0xe9, 0x67, 0xbb, 0x98, 0xd6, 0xb7, 0xd7, 0xbf, 0x82, 5, 0x1e, 0x6c, 0x28, 6, 0, 0}
	startfilter := `\01\05\00\00\00\00\00\05\15\00\00\00\e9\67\bb\98\d6\b7\d7\bf\82\05\1e\6c\28\06\00\00`

	sid, err := ParseSID(start)
	if err != nil {
		t.Fatalf("could not parse sid: %v", err)
	}

	if start != sid.String() {
		t.Error("expected parsed string to be equal")
	}

	if rid := sid.RID(); rid != 1576 {
		t.Errorf("expected rid to be equal: want: 1576, have: %d", rid)
	}

	if sid.FilterString() != startfilter {
		t.Error("expected filter string to be equal")
	}

	buf, err := sid.MarshalBinary()
	if err != nil {
		t.Fatalf("could not marshal sid: %v", err)
	}

	if !bytes.Equal(startbin, buf) {
		t.Error("expected marshaled sid to be equal")
	}

	sid2 := new(SID)
	if err = sid2.UnmarshalBinary(buf); err != nil {
		t.Fatalf("could not unmarshal sid: %v", err)
	}

	if !sid.Equal(sid2) {
		t.Error("expected unmarshaled sid to be equal")
	}

	sid2.IdentifierAuthority = 6
	if sid.Equal(sid2) {
		t.Error("expected sid not to be equal")
	}

	sid2.IdentifierAuthority = 5
	sid2.SubAuthoritys[0] = 0
	if sid.Equal(sid2) {
		t.Error("expected sid not to be equal")
	}

	for _, test := range ErrSIDTests {
		if _, err = ParseSID(test); err == nil {
			t.Errorf("expected test to fail: %s", test)
		}
	}

	for _, test := range ErrSIDBinaryTests {
		if err = sid2.UnmarshalBinary(test); err == nil {
			t.Errorf("expected test to fail: %s", test)
		}
	}
}

func TestSIDMarshalBinaryUsesSliceLength(t *testing.T) {
	sid := &SID{
		Revision:            SIDRevision,
		SubAuthorityLength:  99,
		IdentifierAuthority: 5,
		SubAuthoritys:       []uint32{21, 50},
	}

	buf, err := sid.MarshalBinary()
	if err != nil {
		t.Fatalf("expected marshal to succeed: %v", err)
	}

	expected := []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 50, 0, 0, 0}
	if !bytes.Equal(expected, buf) {
		t.Fatalf("expected marshaled sid %v but got %v", expected, buf)
	}

	if sid.FilterString() != `\01\02\00\00\00\00\00\05\15\00\00\00\32\00\00\00` {
		t.Fatalf("unexpected filter string: %q", sid.FilterString())
	}
}

func TestSIDRID(t *testing.T) {
	withSubs, err := ParseSID("S-1-5-21-1-2-1576")
	if err != nil {
		t.Fatalf("ParseSID failed: %v", err)
	}
	if rid := withSubs.RID(); rid != 1576 {
		t.Errorf("RID() = %d, want 1576", rid)
	}

	// A SID with no sub authorities has no RID; RID must return 0 rather than panic.
	empty := &SID{Revision: SIDRevision, IdentifierAuthority: 5}
	if rid := empty.RID(); rid != 0 {
		t.Errorf("RID() on empty sub authorities = %d, want 0", rid)
	}
}

func TestSIDMarshalBinaryRejectsOversizedAuthority(t *testing.T) {
	// IdentifierAuthority is a 6-byte (48-bit) field per MS-DTYP §2.4.2.1.
	sid := &SID{
		Revision:            SIDRevision,
		IdentifierAuthority: uint64(1) << 48,
		SubAuthoritys:       []uint32{21},
	}

	if _, err := sid.MarshalBinary(); err == nil {
		t.Fatal("expected marshal to fail for oversized identifier authority")
	}
	if sid.FilterString() != "" {
		t.Fatalf("expected empty filter string for invalid sid, got %q", sid.FilterString())
	}
}

func TestSIDRoundTrip(t *testing.T) {
	// Parse → String and Marshal → Unmarshal must both be lossless for well-known SIDs.
	cases := []string{
		"S-1-5-21-2562418665-3218585558-1813906818-1576",
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-1-0",      // Everyone
		"S-1-5-18",     // Local System
	}
	for _, want := range cases {
		t.Run(want, func(t *testing.T) {
			sid, err := ParseSID(want)
			if err != nil {
				t.Fatalf("ParseSID(%q) failed: %v", want, err)
			}
			if got := sid.String(); got != want {
				t.Fatalf("String() = %q, want %q", got, want)
			}

			buf, err := sid.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary failed: %v", err)
			}

			var rt SID
			if err := rt.UnmarshalBinary(buf); err != nil {
				t.Fatalf("UnmarshalBinary failed: %v", err)
			}
			if !sid.Equal(&rt) {
				t.Fatalf("binary round-trip mismatch for %q", want)
			}
		})
	}
}

func TestSIDMarshalBinaryRejectsTooManySubAuthorities(t *testing.T) {
	subs := make([]uint32, 256)
	sid := &SID{
		Revision:            SIDRevision,
		IdentifierAuthority: 5,
		SubAuthoritys:       subs,
	}

	if _, err := sid.MarshalBinary(); err == nil {
		t.Fatal("expected marshal to fail for too many sub authorities")
	}

	if sid.FilterString() != "" {
		t.Fatalf("expected empty filter string for invalid sid but got %q", sid.FilterString())
	}
}
