// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"encoding/asn1"
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
		if len(tbl.ByName) != len(tbl.ByOID) {
			t.Errorf("table %q: ByName has %d entries, ByOID has %d; the maps must be the same size",
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
