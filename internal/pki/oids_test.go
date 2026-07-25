// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestOIDByName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"commonName":         "2.5.4.3",
		"surname":            "2.5.4.4",
		"givenName":          "2.5.4.42",
		"displayName":        "2.16.840.1.113730.3.1.241",
		"uid":                "0.9.2342.19200300.100.1.1",
		"organization":       "2.5.4.10",
		"organizationalUnit": "2.5.4.11",
		"emailAddress":       "1.2.840.113549.1.9.1",
		"subjectAltName":     "2.5.29.17",
		"basicConstraints":   "2.5.29.19",
		"clientAuth":         "1.3.6.1.5.5.7.3.2",
	} {
		got, err := OIDByName(name)
		if err != nil {
			t.Errorf("OIDByName(%q) returned error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("OIDByName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestOIDByNameUnknownIsAnError(t *testing.T) {
	t.Parallel()
	// Spec section 11: functions must error on unknown input rather than
	// returning empty, so a typo fails at plan time.
	if _, err := OIDByName("commonNam"); err == nil {
		t.Fatal("OIDByName(\"commonNam\") returned nil error, want an error")
	}
}

func TestNameByOID(t *testing.T) {
	t.Parallel()
	got, err := NameByOID("2.5.4.4")
	if err != nil {
		t.Fatalf("NameByOID: %v", err)
	}
	if got != "surname" {
		t.Fatalf("NameByOID(\"2.5.4.4\") = %q, want \"surname\"", got)
	}
	if _, err := NameByOID("1.2.3.4.5.6.7.8.9"); err == nil {
		t.Fatal("NameByOID on an unknown OID returned nil error, want an error")
	}
}

// TestTablesAreBidirectional is the completeness check required by spec
// section 10: every ByName entry must round-trip through ByOID and vice versa,
// so the two halves of every table can never drift apart.
func TestTablesAreBidirectional(t *testing.T) {
	t.Parallel()
	tables := Tables()
	if len(tables) != 5 {
		t.Fatalf("Tables() returned %d groups, want 5", len(tables))
	}
	wantNames := []string{"dn_attributes", "extensions", "extended_key_usages", "key_usages", "signature_algorithms"}
	for i, want := range wantNames {
		if tables[i].Name != want {
			t.Errorf("Tables()[%d].Name = %q, want %q", i, tables[i].Name, want)
		}
	}
	for _, tbl := range tables {
		if len(tbl.ByName) == 0 {
			t.Errorf("table %q has an empty ByName map", tbl.Name)
		}
		// Every entry in ByOID must round-trip back through ByName. This holds
		// for all five groups, including signature_algorithms, where the
		// reverse direction is a strict subset (see below).
		for oid, name := range tbl.ByOID {
			back, ok := tbl.ByName[name]
			if !ok {
				t.Errorf("table %q: ByOID[%q] = %q but ByName is missing that key", tbl.Name, oid, name)
				continue
			}
			if back != oid {
				t.Errorf("table %q: %q -> %q -> %q, want the original OID back", tbl.Name, oid, name, back)
			}
		}
	}

	// Four of the five groups are strict bijections. signature_algorithms is
	// not, and cannot be: see TestSignatureAlgorithmTableIsNotBijective.
	for _, tbl := range tables {
		if tbl.Name == "signature_algorithms" {
			continue
		}
		if len(tbl.ByName) != len(tbl.ByOID) {
			t.Errorf("table %q: ByName has %d entries, ByOID has %d; this group must be a strict bijection",
				tbl.Name, len(tbl.ByName), len(tbl.ByOID))
		}
		for name, oid := range tbl.ByName {
			back, ok := tbl.ByOID[oid]
			if !ok {
				t.Errorf("table %q: ByName[%q] = %q but ByOID is missing that key", tbl.Name, name, oid)
				continue
			}
			if back != name {
				t.Errorf("table %q: %q -> %q -> %q, want the original name back", tbl.Name, name, oid, back)
			}
		}
	}
}

// TestSignatureAlgorithmTableIsNotBijective documents the one place the
// name-to-OID mapping is genuinely many-to-one, so nobody "fixes" it by
// inventing OID arcs that do not exist.
//
// RFC 8017 registers a single OID for RSASSA-PSS, 1.2.840.113549.1.1.10. The
// hash lives in the AlgorithmIdentifier's PSS parameters, not in the OID, so
// SHA256-RSAPSS, SHA384-RSAPSS, and SHA512-RSAPSS all share it. An OID alone
// therefore cannot name a PSS variant, and the reverse map omits it rather
// than guessing a hash or fabricating a sub-arc.
func TestSignatureAlgorithmTableIsNotBijective(t *testing.T) {
	t.Parallel()
	const pssOID = "1.2.840.113549.1.1.10"

	var sigs Table
	for _, tbl := range Tables() {
		if tbl.Name == "signature_algorithms" {
			sigs = tbl
		}
	}
	if sigs.Name == "" {
		t.Fatal("Tables() has no signature_algorithms group")
	}

	// All three PSS names are present in ByName and all three share the one
	// real registered OID.
	for _, name := range []string{"SHA256-RSAPSS", "SHA384-RSAPSS", "SHA512-RSAPSS"} {
		got, ok := sigs.ByName[name]
		if !ok {
			t.Errorf("ByName is missing %q", name)
			continue
		}
		if got != pssOID {
			t.Errorf("ByName[%q] = %q, want the single registered RSASSA-PSS OID %q", name, got, pssOID)
		}
	}

	// The shared OID is absent from the reverse map, because it does not
	// identify one algorithm.
	if name, ok := sigs.ByOID[pssOID]; ok {
		t.Errorf("ByOID[%q] = %q; the shared RSASSA-PSS OID must not appear in the reverse map, because it does not determine the hash", pssOID, name)
	}

	// No fabricated sub-arcs of the PSS OID anywhere in either direction.
	for name, oid := range sigs.ByName {
		if strings.HasPrefix(oid, pssOID+".") {
			t.Errorf("ByName[%q] = %q invents a sub-arc of the RSASSA-PSS OID; no such arc is registered", name, oid)
		}
	}
	for oid := range sigs.ByOID {
		if strings.HasPrefix(oid, pssOID+".") {
			t.Errorf("ByOID has key %q, which invents a sub-arc of the RSASSA-PSS OID", oid)
		}
	}

	// Every non-PSS name still round-trips, so the exception is narrow.
	for _, name := range []string{"SHA256-RSA", "ECDSA-SHA384", "Ed25519"} {
		oid, ok := sigs.ByName[name]
		if !ok {
			t.Errorf("ByName is missing %q", name)
			continue
		}
		if back := sigs.ByOID[oid]; back != name {
			t.Errorf("%q -> %q -> %q, want the original name back", name, oid, back)
		}
	}
}

// TestDNAttributesCoverEnginePy pins the exact set of DN attributes the
// existing homelab issuer emits (reconcile/engine.py lines 45-58). Losing any
// of these breaks adoption of the certificates already on devices.
func TestDNAttributesCoverEnginePy(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"commonName", "uid", "displayName", "givenName", "surname", "organization", "organizationalUnit"} {
		if _, err := DNAttributeOID(name); err != nil {
			t.Errorf("DNAttributeOID(%q): %v", name, err)
		}
	}
}

func TestParseOID(t *testing.T) {
	t.Parallel()
	got, err := ParseOID("2.5.4.3")
	if err != nil {
		t.Fatalf("ParseOID: %v", err)
	}
	if !got.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
		t.Fatalf("ParseOID(\"2.5.4.3\") = %v, want 2.5.4.3", got)
	}
	if FormatOID(got) != "2.5.4.3" {
		t.Fatalf("FormatOID round-trip = %q, want \"2.5.4.3\"", FormatOID(got))
	}
	for _, bad := range []string{"", "2", "2.", ".2.5", "2..5", "2.5.4.x", "2.5.4.-1", "2.5.4.3 "} {
		if _, err := ParseOID(bad); err == nil {
			t.Errorf("ParseOID(%q) returned nil error, want an error", bad)
		}
	}
}

func TestExtKeyUsageOIDAcceptsNamesAndRawOIDs(t *testing.T) {
	t.Parallel()
	// Spec section 5.3: extended_key_usage.usages takes names or raw OIDs.
	byName, err := ExtKeyUsageOID("clientAuth")
	if err != nil {
		t.Fatalf("ExtKeyUsageOID(\"clientAuth\"): %v", err)
	}
	if FormatOID(byName) != "1.3.6.1.5.5.7.3.2" {
		t.Fatalf("clientAuth = %s, want 1.3.6.1.5.5.7.3.2", FormatOID(byName))
	}
	byOID, err := ExtKeyUsageOID("1.3.6.1.4.1.311.20.2.2")
	if err != nil {
		t.Fatalf("ExtKeyUsageOID on a raw OID: %v", err)
	}
	if FormatOID(byOID) != "1.3.6.1.4.1.311.20.2.2" {
		t.Fatalf("raw OID = %s, want it unchanged", FormatOID(byOID))
	}
	if _, err := ExtKeyUsageOID("clientAuthh"); err == nil {
		t.Fatal("ExtKeyUsageOID on an unknown name returned nil error, want an error")
	}
}

func TestKeyUsageBits(t *testing.T) {
	t.Parallel()
	// RFC 5280 4.2.1.3 bit positions.
	for name, want := range map[string]int{
		"digitalSignature": 0,
		"nonRepudiation":   1,
		"keyEncipherment":  2,
		"dataEncipherment": 3,
		"keyAgreement":     4,
		"keyCertSign":      5,
		"crlSign":          6,
		"encipherOnly":     7,
		"decipherOnly":     8,
	} {
		got, err := KeyUsageBit(name)
		if err != nil {
			t.Errorf("KeyUsageBit(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("KeyUsageBit(%q) = %d, want %d", name, got, want)
		}
		back, err := KeyUsageBitName(want)
		if err != nil || back != name {
			t.Errorf("KeyUsageBitName(%d) = %q, %v; want %q, nil", want, back, err, name)
		}
	}
	if _, err := KeyUsageBit("digitalSignatures"); err == nil {
		t.Fatal("KeyUsageBit on an unknown name returned nil error, want an error")
	}
}

func TestSignatureAlgorithmNames(t *testing.T) {
	t.Parallel()
	got, err := SignatureAlgorithmByName("SHA256-RSA")
	if err != nil {
		t.Fatalf("SignatureAlgorithmByName: %v", err)
	}
	if got != x509.SHA256WithRSA {
		t.Fatalf("SHA256-RSA = %v, want x509.SHA256WithRSA", got)
	}
	name, err := SignatureAlgorithmName(x509.ECDSAWithSHA384)
	if err != nil {
		t.Fatalf("SignatureAlgorithmName: %v", err)
	}
	if name != "ECDSA-SHA384" {
		t.Fatalf("ECDSAWithSHA384 = %q, want \"ECDSA-SHA384\"", name)
	}
	if _, err := SignatureAlgorithmByName("MD5-RSA"); err == nil {
		t.Fatal("SignatureAlgorithmByName(\"MD5-RSA\") returned nil error; MD5 must not be offered")
	}
}
