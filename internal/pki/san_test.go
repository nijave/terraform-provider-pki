// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
)

func TestSANExtensionOIDAndEmptiness(t *testing.T) {
	t.Parallel()
	if !(SAN{}).IsEmpty() {
		t.Error("a zero SAN is not reported empty")
	}
	// Critical alone does not make a SAN non-empty; there would be nothing to
	// mark critical.
	if !(SAN{Critical: true}).IsEmpty() {
		t.Error("a SAN with only Critical set is not reported empty")
	}
	if (SAN{DNSNames: []string{"a"}}).IsEmpty() {
		t.Error("a SAN with a DNS name is reported empty")
	}

	ext, err := SAN{DNSNames: []string{"a.example"}}.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if got := FormatOID(ext.Id); got != "2.5.29.17" {
		t.Fatalf("SAN extension OID = %s, want 2.5.29.17", got)
	}
}

// TestSANRoundTripsAllFourTypes covers every GeneralName the provider supports
// (spec section 5.2). otherName, registeredID, and directoryName are out of
// scope and belong in extra_extension.
func TestSANRoundTripsAllFourTypes(t *testing.T) {
	t.Parallel()
	original := SAN{
		DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info", "alt.example"},
		EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("fd00::5")},
		URIs:           []string{"spiffe://homelab/nick-ipad"},
	}
	ext, err := original.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	parsed, err := ParseSANExtension(ext)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}

	if len(parsed.DNSNames) != 2 || parsed.DNSNames[0] != original.DNSNames[0] || parsed.DNSNames[1] != original.DNSNames[1] {
		t.Errorf("DNS names = %v, want %v", parsed.DNSNames, original.DNSNames)
	}
	if len(parsed.EmailAddresses) != 2 || parsed.EmailAddresses[0] != original.EmailAddresses[0] || parsed.EmailAddresses[1] != original.EmailAddresses[1] {
		t.Errorf("email addresses = %v, want %v", parsed.EmailAddresses, original.EmailAddresses)
	}
	if len(parsed.IPAddresses) != 2 {
		t.Fatalf("IP addresses = %v, want 2 entries", parsed.IPAddresses)
	}
	if !parsed.IPAddresses[0].Equal(original.IPAddresses[0]) || !parsed.IPAddresses[1].Equal(original.IPAddresses[1]) {
		t.Errorf("IP addresses = %v, want %v", parsed.IPAddresses, original.IPAddresses)
	}
	if len(parsed.URIs) != 1 || parsed.URIs[0] != original.URIs[0] {
		t.Errorf("URIs = %v, want %v", parsed.URIs, original.URIs)
	}
}

// TestSANPreservesWithinTypeOrder pins the ordering guarantee from spec section
// 5.2. Entries keep their declared order within a type, and types are emitted
// in the fixed order dns, email, ip, uri -- which is what both openssl's config
// ordering and Go's x509 marshaller produce for the homelab certificates
// (reconcile/engine.py lines 71-78 lists DNS first, then emails).
func TestSANPreservesWithinTypeOrder(t *testing.T) {
	t.Parallel()
	s := SAN{
		DNSNames:       []string{"z.example", "a.example", "m.example"},
		EmailAddresses: []string{"z@example.com", "a@example.com"},
	}
	ext, err := s.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	parsed, err := ParseSANExtension(ext)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	for i, want := range s.DNSNames {
		if parsed.DNSNames[i] != want {
			t.Errorf("DNS name %d = %q, want %q; sorting is not permitted", i, parsed.DNSNames[i], want)
		}
	}
	for i, want := range s.EmailAddresses {
		if parsed.EmailAddresses[i] != want {
			t.Errorf("email %d = %q, want %q; sorting is not permitted", i, parsed.EmailAddresses[i], want)
		}
	}
}

// TestSANCriticalityForcedWhenSubjectEmpty implements RFC 5280 4.2.1.6: if the
// subject is empty the SAN must be marked critical, because it is then the only
// identity in the certificate.
func TestSANCriticalityForcedWhenSubjectEmpty(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		configured   bool
		subjectEmpty bool
		want         bool
	}{
		{configured: false, subjectEmpty: false, want: false},
		{configured: true, subjectEmpty: false, want: true},
		{configured: false, subjectEmpty: true, want: true}, // forced
		{configured: true, subjectEmpty: true, want: true},
	} {
		ext, err := SAN{DNSNames: []string{"a.example"}, Critical: tc.configured}.Extension(tc.subjectEmpty)
		if err != nil {
			t.Errorf("Extension(configured=%v, subjectEmpty=%v): %v", tc.configured, tc.subjectEmpty, err)
			continue
		}
		if ext.Critical != tc.want {
			t.Errorf("Extension(configured=%v, subjectEmpty=%v).Critical = %v, want %v",
				tc.configured, tc.subjectEmpty, ext.Critical, tc.want)
		}
	}
}

func TestSANExtensionRejectsEmptyAndInvalid(t *testing.T) {
	t.Parallel()
	// An empty SAN extension is invalid DER per RFC 5280 (GeneralNames must
	// have at least one entry); callers must omit the extension instead.
	if _, err := (SAN{}).Extension(false); err == nil {
		t.Error("Extension on an empty SAN returned nil error, want an error")
	}
	for label, s := range map[string]SAN{
		"nil ip":          {IPAddresses: []net.IP{nil}},
		"malformed ip":    {IPAddresses: []net.IP{{1, 2, 3}}},
		"empty dns":       {DNSNames: []string{""}},
		"empty email":     {EmailAddresses: []string{""}},
		"empty uri":       {URIs: []string{""}},
		"non-ascii dns":   {DNSNames: []string{"nïck.example"}},
		"non-ascii email": {EmailAddresses: []string{"nïck@example.com"}},
		"unparseable uri": {URIs: []string{":://nope"}},
		"relative uri":    {URIs: []string{"/just/a/path"}},
	} {
		if _, err := s.Extension(false); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestParseSANExtensionRejectsGarbage(t *testing.T) {
	t.Parallel()
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for label, ext := range map[string]pkix.Extension{
		"wrong oid": {Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x00}},
		"not asn1":  {Id: sanOID, Value: []byte("hello")},
		"empty":     {Id: sanOID, Value: nil},
	} {
		if _, err := ParseSANExtension(ext); err == nil {
			t.Errorf("ParseSANExtension(%s) returned nil error, want an error", label)
		}
	}
}

// TestParseSANExtensionIgnoresUnsupportedGeneralNames matters for import: a
// certificate issued elsewhere may carry an otherName. Parsing must not fail --
// that would make the certificate unimportable -- but the value cannot be
// represented, so the caller needs to know it was dropped.
func TestParseSANExtensionIgnoresUnsupportedGeneralNames(t *testing.T) {
	t.Parallel()
	// GeneralNames containing one dNSName [2] and one registeredID [8].
	value, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("a.example")},
		{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{0x2a, 0x03, 0x04}},
	})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	parsed, err := ParseSANExtension(pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value})
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "a.example" {
		t.Fatalf("DNS names = %v, want [a.example]", parsed.DNSNames)
	}
}

func TestParseIPs(t *testing.T) {
	t.Parallel()
	got, err := ParseIPs([]string{"10.0.0.5", "fd00::5"})
	if err != nil {
		t.Fatalf("ParseIPs: %v", err)
	}
	if len(got) != 2 || !got[0].Equal(net.ParseIP("10.0.0.5")) || !got[1].Equal(net.ParseIP("fd00::5")) {
		t.Fatalf("ParseIPs = %v, want [10.0.0.5 fd00::5]", got)
	}
	for _, bad := range [][]string{{"10.0.0.256"}, {"not-an-ip"}, {""}, {"10.0.0.0/24"}} {
		if _, err := ParseIPs(bad); err == nil {
			t.Errorf("ParseIPs(%v) returned nil error, want an error", bad)
		}
	}
}

func TestFindExtension(t *testing.T) {
	t.Parallel()
	exts := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{1}},
		{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{2}},
	}
	got, ok := FindExtension(exts, asn1.ObjectIdentifier{2, 5, 29, 17})
	if !ok || got.Value[0] != 2 {
		t.Fatalf("FindExtension returned %v, %v; want the SAN extension", got, ok)
	}
	if _, ok := FindExtension(exts, asn1.ObjectIdentifier{2, 5, 29, 19}); ok {
		t.Fatal("FindExtension found an extension that is not present")
	}
	if _, ok := FindExtension(nil, asn1.ObjectIdentifier{2, 5, 29, 19}); ok {
		t.Fatal("FindExtension on a nil slice reported a hit")
	}
}
