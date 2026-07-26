// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
)

// goldenExtensionOIDs is the exact set of extensions testdata/leaf.crt carries,
// pinned as a literal rather than derived from the certificate.
//
// It exists to stop the two comparison loops below from passing vacuously. Both
// iterate maps keyed by OID, and an empty map makes every assertion inside them
// a no-op: if the reference failed to parse into extensions, or if a future
// refactor stopped populating one side, the test would report success while
// comparing nothing at all. Asserting the reference's OID set against this
// literal first means the loops cannot run over an empty or truncated map
// without the test already having failed.
//
// The set is what ext.cnf asks for (basicConstraints, keyUsage,
// extendedKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier,
// subjectAltName) and nothing else. Regenerating the fixtures under an openssl
// that adds a seventh extension by default must fail here loudly rather than
// silently widen what the test covers.
//
// If you are reading this because that failure just happened, it is telling you
// the fixture changed, not that this list is wrong, and the message names the OIDs
// that appeared or vanished. The question to answer is whether this package should
// emit the new extension too: an openssl default that CertTemplate has no
// equivalent for is a real gap in the provider, and this test is how you find out
// about it, which is the entire reason the set is pinned rather than derived from
// the fixture.
//
// So there are two correct responses, and adding the OID to this list is not one
// of them on its own -- the guard immediately below the first one requires our
// certificate to carry the same number of extensions, so a seventh entry here
// fails again with "our certificate carries 6 extensions, want 7" until the
// provider emits it too. Either teach CertTemplate to produce the extension and
// then add the OID here, or regenerate the fixture with the extension suppressed
// and leave this list alone. Both keep the pinned set and the compared set
// identical, which is the property that stops the loops below from passing over
// something they never looked at.
var goldenExtensionOIDs = []string{
	"2.5.29.14", // subjectKeyIdentifier
	"2.5.29.15", // keyUsage
	"2.5.29.17", // subjectAltName
	"2.5.29.19", // basicConstraints
	"2.5.29.35", // authorityKeyIdentifier
	"2.5.29.37", // extendedKeyUsage
}

// TestGoldenMatchesThePythonIssuer reproduces the certificate that
// reconcile/engine.py produces for nick-ipad from config.hcl's identity, and
// asserts field-by-field equality against the openssl-generated reference in
// testdata/.
//
// This is spec section 10's cross-validation test. Its purpose is to prove the
// provider is a drop-in replacement for the Python issuer before the migration
// spec cuts anything over. See testdata/README.md for how leaf.crt was
// generated.
//
// The identity below is not invented. Every value was checked against the
// reference deployment's own config.hcl -- k8s-manifests/vmubtkube-a/homelab-pki
// -- on 2026-07-26, field by field, and all of them match: users.nick.identity's
// surname Venenga, given_name Nick, display_name "Nick V", organization homelab
// and uid nick; primary_email nick@venenga.com followed by
// additional_email_addresses ["nijave@gmail.com"] as the SAN rfc822Names, in that
// order; ekus ["clientAuth"]; and nick-ipad present in users.nick.devices.
//
// Two of them are absences rather than values, and both are load-bearing.
// common_name is commented out there, which is what makes the CN the per-device
// default <device>.ha.apps.somemissing.info rather than a shared per-user name --
// so nick-ipad.ha.apps.somemissing.info below is derived, not configured, and a
// config.hcl that uncommented common_name would make this fixture wrong in a way
// no assertion here would notice. organizational_units is commented out too,
// which is why the DN has six attributes and no OU.
//
// Anyone re-checking this should compare against that file rather than trusting
// this comment, since it is a copy of state that lives in another repository.
func TestGoldenMatchesThePythonIssuer(t *testing.T) {
	t.Parallel()

	caCertPEM, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		t.Fatalf("reading testdata/ca.crt: %v", err)
	}
	caKeyPEM, err := os.ReadFile("testdata/ca.key")
	if err != nil {
		t.Fatalf("reading testdata/ca.key: %v", err)
	}
	leafKeyPEM, err := os.ReadFile("testdata/leaf.key")
	if err != nil {
		t.Fatalf("reading testdata/leaf.key: %v", err)
	}
	referencePEM, err := os.ReadFile("testdata/leaf.crt")
	if err != nil {
		t.Fatalf("reading testdata/leaf.crt: %v", err)
	}

	ca, err := ParseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ca): %v", err)
	}
	caKey, err := ParsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM(ca): %v", err)
	}
	leafKey, err := ParsePrivateKeyPEM(leafKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM(leaf): %v", err)
	}
	reference, err := ParseCertificatePEM(referencePEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(reference): %v", err)
	}

	// The ordered subject form is required here: engine.py places displayName
	// between UID and GN, which the canonical named-field order cannot produce.
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	subject := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
	}}

	certPEM, err := CreateCertificate(CertTemplate{
		Subject: subject,
		SAN: SAN{
			DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info"},
			EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
		},
		Serial:           big.NewInt(0x2001),
		NotBefore:        reference.NotBefore,
		NotAfter:         reference.NotAfter,
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}, Critical: false},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	got, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// The subject DN must be byte-identical. This is the assertion that
	// justifies the StringType design: openssl emitted UTF8String because of
	// string_mask = utf8only, and Go's default would have emitted
	// PrintableString.
	//
	// A zero-length RawSubject on either side would make bytes.Equal true
	// against another zero-length one, so both are checked to be non-empty
	// first. x509.ParseCertificate always fills RawSubject for a non-empty DN,
	// but the guard is what makes this assertion's failure mode "the DNs differ"
	// rather than "neither DN was read".
	if len(reference.RawSubject) == 0 {
		t.Fatal("the reference certificate parsed with an empty RawSubject; the fixture or the parser is broken")
	}
	if len(got.RawSubject) == 0 {
		t.Fatal("our certificate parsed with an empty RawSubject")
	}
	if !bytes.Equal(got.RawSubject, reference.RawSubject) {
		t.Errorf("subject DN is not byte-identical to openssl's\n openssl: % x\n    ours: % x", reference.RawSubject, got.RawSubject)
	}
	if !bytes.Equal(got.RawIssuer, reference.RawIssuer) {
		t.Errorf("issuer DN is not byte-identical to openssl's\n openssl: % x\n    ours: % x", reference.RawIssuer, got.RawIssuer)
	}
	if got.SerialNumber.Cmp(reference.SerialNumber) != 0 {
		t.Errorf("serial = %s, want %s", got.SerialNumber, reference.SerialNumber)
	}
	if got.SignatureAlgorithm != reference.SignatureAlgorithm {
		t.Errorf("signature algorithm = %v, want %v", got.SignatureAlgorithm, reference.SignatureAlgorithm)
	}

	// Every extension openssl emitted must be present with the same
	// criticality and the same value. authorityKeyIdentifier is compared
	// separately below because openssl's "keyid, issuer" form and Go's keyid
	// form can differ in what they include.
	//
	// Note both maps are keyed by OID rather than compared positionally. That
	// is required, not stylistic: x509.CreateCertificate prepends the AKI it
	// synthesizes, so the issued order differs from CertTemplate.Extensions()'
	// order, and openssl's order differs from both. Only the set and the
	// per-OID values are comparable. Measured on these fixtures, openssl wrote
	//
	//	basicConstraints, keyUsage, extendedKeyUsage, subjectKeyIdentifier,
	//	authorityKeyIdentifier, subjectAltName
	//
	// while this package issued
	//
	//	authorityKeyIdentifier, basicConstraints, keyUsage, extendedKeyUsage,
	//	subjectAltName, subjectKeyIdentifier
	//
	// -- three of six positions disagree, and every one of them holds an
	// identical value.
	akiOID := "2.5.29.35"
	refExts := map[string]pkix.Extension{}
	for _, e := range reference.Extensions {
		refExts[FormatOID(e.Id)] = e
	}
	gotExts := map[string]pkix.Extension{}
	for _, e := range got.Extensions {
		gotExts[FormatOID(e.Id)] = e
	}
	// Both loops below iterate a map, so an empty map would make each of their
	// bodies unreachable and every assertion in them vacuously satisfied.
	// Pinning the reference's OID set against a literal, and requiring ours to
	// hold the same number of entries, is what makes that impossible: neither
	// loop can be reached with fewer than the six extensions the fixture is
	// known to carry.
	if diff := diffOIDSets(refExts, goldenExtensionOIDs); diff != "" {
		t.Fatalf("the reference certificate does not carry the expected extension set, so the comparison below would not compare what this test claims: %s", diff)
	}
	if len(gotExts) != len(goldenExtensionOIDs) {
		t.Fatalf("our certificate carries %d extensions (%v), want %d", len(gotExts), sortedOIDs(gotExts), len(goldenExtensionOIDs))
	}
	for oid, want := range refExts {
		if oid == akiOID {
			continue
		}
		have, ok := gotExts[oid]
		if !ok {
			t.Errorf("extension %s is present in openssl's output and missing from ours", oid)
			continue
		}
		if have.Critical != want.Critical {
			t.Errorf("extension %s Critical = %v, want %v", oid, have.Critical, want.Critical)
		}
		if !bytes.Equal(have.Value, want.Value) {
			t.Errorf("extension %s value differs\n openssl: % x\n    ours: % x", oid, want.Value, have.Value)
		}
	}
	for oid := range gotExts {
		if oid == akiOID {
			continue
		}
		if _, ok := refExts[oid]; !ok {
			t.Errorf("extension %s is present in ours and absent from openssl's output", oid)
		}
	}
	// The AKI must at least carry the issuer's key identifier.
	if len(reference.AuthorityKeyId) == 0 {
		t.Fatal("the reference certificate has an empty AuthorityKeyId; openssl's authorityKeyIdentifier = keyid did not resolve")
	}
	if !bytes.Equal(got.AuthorityKeyId, reference.AuthorityKeyId) {
		t.Errorf("authorityKeyIdentifier keyid = % x, want % x", got.AuthorityKeyId, reference.AuthorityKeyId)
	}
	if len(reference.SubjectKeyId) == 0 {
		t.Fatal("the reference certificate has an empty SubjectKeyId; openssl's subjectKeyIdentifier = hash did not resolve")
	}
	if !bytes.Equal(got.SubjectKeyId, reference.SubjectKeyId) {
		t.Errorf("subjectKeyIdentifier = % x, want % x; both should be the RFC 5280 method 1 SHA-1", got.SubjectKeyId, reference.SubjectKeyId)
	}
}

// TestGoldenImportPlansClean is the library-level rehearsal of spec section 8's
// import-fidelity requirement: parse the openssl-generated certificate, rebuild
// a template from what was parsed, and confirm the comparison reports nothing.
// Plan 2's acceptance test does the same thing through Terraform.
func TestGoldenImportPlansClean(t *testing.T) {
	t.Parallel()

	referencePEM, err := os.ReadFile("testdata/leaf.crt")
	if err != nil {
		t.Fatalf("reading testdata/leaf.crt: %v", err)
	}
	caCertPEM, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		t.Fatalf("reading testdata/ca.crt: %v", err)
	}
	reference, err := ParseCertificatePEM(referencePEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	ca, err := ParseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ca): %v", err)
	}

	subject, err := ParseSubjectDER(reference.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	// The DN is checked to have parsed into the six attributes engine.py emits
	// before its bytes are compared. Re-encoding an empty Subject yields an
	// empty RDNSequence, which would still differ from the reference here -- but
	// the assertion below reads as "the round trip is byte-exact", and it should
	// not be able to hold for a subject that carries nothing.
	if len(subject.Attributes) != 6 {
		t.Fatalf("the reference DN parsed into %d attributes (%s), want 6", len(subject.Attributes), subject)
	}
	// Re-encoding the parsed DN must reproduce the original bytes, or nothing
	// downstream can plan clean.
	reencoded, err := subject.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	if !bytes.Equal(reencoded, reference.RawSubject) {
		t.Fatalf("re-encoding openssl's DN is not byte-exact\n original: % x\n re-encoded: % x", reference.RawSubject, reencoded)
	}
	// Every value openssl wrote is a UTF8String, because engine.py sets
	// string_mask = utf8only. This is asserted in its own right rather than
	// left implicit in the byte comparison above: the round trip would also be
	// byte-exact if the parser and the encoder agreed on a wrong tag, and the
	// tag is the specific thing that must survive adoption.
	for i, a := range subject.Attributes {
		if a.StringType != StringTypeUTF8 {
			t.Errorf("subject attribute %d (%s) parsed as %q, want %q", i, FormatOID(a.OID), a.StringType, StringTypeUTF8)
		}
	}

	sanExt, ok := FindExtension(reference.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("the reference certificate has no SAN extension")
	}
	san, err := ParseSANExtension(sanExt)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	san.Critical = sanExt.Critical
	// Re-encoding the parsed SAN must also be byte-exact, which is what proves
	// the fixed dns/email/ip/uri emission order matches openssl's.
	rebuilt, err := san.Extension(subject.IsEmpty())
	if err != nil {
		t.Fatalf("SAN Extension: %v", err)
	}
	if !bytes.Equal(rebuilt.Value, sanExt.Value) {
		t.Fatalf("re-encoding openssl's SAN is not byte-exact\n original: % x\n re-encoded: % x", sanExt.Value, rebuilt.Value)
	}

	bc, err := ParseBasicConstraints(mustFindExt(t, reference.Extensions, "2.5.29.19"))
	if err != nil {
		t.Fatalf("ParseBasicConstraints: %v", err)
	}
	ku, err := ParseKeyUsage(mustFindExt(t, reference.Extensions, "2.5.29.15"))
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	eku, err := ParseExtKeyUsage(mustFindExt(t, reference.Extensions, "2.5.29.37"))
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}

	drift, err := CompareCertificate(CompareInput{
		Desired: CertTemplate{
			Subject:          subject,
			SAN:              san,
			Serial:           reference.SerialNumber,
			NotBefore:        reference.NotBefore,
			NotAfter:         reference.NotAfter,
			BasicConstraints: &bc,
			KeyUsage:         &ku,
			ExtKeyUsage:      &eku,
		},
		DesiredPublicKey: reference.PublicKey,
		Actual:           reference,
		CA:               ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("an imported openssl-issued certificate reported drift: %v", drift)
	}
}

// diffOIDSets reports how the keys of exts differ from want, or "" when they are
// the same set. It exists so the golden test can prove its comparison maps hold
// what it thinks they hold before iterating them.
func diffOIDSets(exts map[string]pkix.Extension, want []string) string {
	wanted := make(map[string]bool, len(want))
	for _, oid := range want {
		wanted[oid] = true
	}
	var missing, extra []string
	for _, oid := range want {
		if _, ok := exts[oid]; !ok {
			missing = append(missing, oid)
		}
	}
	for oid := range exts {
		if !wanted[oid] {
			extra = append(extra, oid)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	slices.Sort(extra)
	return "missing " + joinOrNone(missing) + ", unexpected " + joinOrNone(extra)
}

// sortedOIDs returns exts' keys in a deterministic order, for error messages.
func sortedOIDs(exts map[string]pkix.Extension) []string {
	oids := make([]string, 0, len(exts))
	for oid := range exts {
		oids = append(oids, oid)
	}
	slices.Sort(oids)
	return oids
}

// joinOrNone renders a possibly-empty OID list for a diff message. The explicit
// "none" matters: strings.Join of an empty slice is "", which would render as
// "missing , unexpected 2.5.29.99" and read like a formatting bug.
func joinOrNone(oids []string) string {
	if len(oids) == 0 {
		return "none"
	}
	return strings.Join(oids, " ")
}
