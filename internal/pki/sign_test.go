// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCreateCertRequestRoundTrip(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	subject := NamedSubject{
		CommonName:   "nick-ipad.ha.apps.somemissing.info",
		UID:          "nick",
		GivenName:    "Nick",
		Surname:      "Venenga",
		Organization: "homelab",
	}.Expand()
	san := SAN{
		DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info"},
		EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
	}

	csrPEM, err := CreateCertRequest(key, CertRequestTemplate{Subject: subject, SAN: san})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}
	csr, err := ParseCertRequestPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCertRequestPEM: %v", err)
	}

	wantDN, err := subject.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	if !bytes.Equal(csr.RawSubject, wantDN) {
		t.Errorf("CSR subject is not byte-identical to the template's DN\n want: % x\n  got: % x", wantDN, csr.RawSubject)
	}

	parsedSubject, err := ParseSubjectDER(csr.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	if !parsedSubject.Equal(subject) {
		t.Errorf("CSR subject = %s, want %s", parsedSubject.String(), subject.String())
	}

	sanExt, ok := FindExtension(csr.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("CSR carries no subjectAltName extension")
	}
	parsedSAN, err := ParseSANExtension(sanExt)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	if len(parsedSAN.EmailAddresses) != 2 {
		t.Errorf("CSR SAN email addresses = %v, want 2 entries", parsedSAN.EmailAddresses)
	}
}

func TestParseCertRequestPEMRejectsABrokenSignature(t *testing.T) {
	t.Parallel()
	// data "pki_cert_request" reports signature_valid, and a CSR handed over by
	// a device or another team is exactly where a bad signature shows up.
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM, err := CreateCertRequest(key, CertRequestTemplate{
		Subject: NamedSubject{CommonName: "cn"}.Expand(),
	})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}
	// Flip a byte in the middle of the base64 body.
	tampered := append([]byte(nil), csrPEM...)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}
	if _, err := ParseCertRequestPEM(tampered); err == nil {
		t.Fatal("ParseCertRequestPEM accepted a tampered CSR")
	}
}

func TestCreateCertificateSelfSigned(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial := big.NewInt(0x2001)
	notBefore := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "homelab-ca", Organization: "homelab"}.Expand(),
		Serial:           serial,
		NotBefore:        notBefore,
		NotAfter:         notBefore.Add(175320 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign", "crlSign"}, Critical: true},
	}
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	if cert.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("serial = %s, want %s", cert.SerialNumber, serial)
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		t.Error("a self-signed certificate's subject and issuer differ")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if len(cert.SubjectKeyId) != 20 {
		t.Errorf("SubjectKeyId is %d bytes, want 20; a CA needs one to sign CRLs", len(cert.SubjectKeyId))
	}
	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %s, want %s", cert.NotBefore, notBefore)
	}
}

func TestCreateCertificateCASignedChainVerifies(t *testing.T) {
	t.Parallel()
	// Spec section 10's first acceptance criterion, proven at the library level:
	// root -> intermediate -> leaf verifies with x509.Certificate.Verify.
	root, rootKey := testCA(t, nil, nil, "homelab-root")
	inter, interKey := testCA(t, root, rootKey, "homelab-intermediate")

	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "nick-ipad.ha.apps.somemissing.info"}.Expand(),
		SAN:              SAN{DNSNames: []string{"nick-ipad.ha.apps.somemissing.info"}},
		Serial:           big.NewInt(0x2002),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(leafKey), inter, interKey)
	if err != nil {
		t.Fatalf("CreateCertificate (leaf): %v", err)
	}
	leaf, err := ParseCertificatePEM(leafPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}

	if !bytes.Equal(leaf.AuthorityKeyId, inter.SubjectKeyId) {
		t.Error("leaf authorityKeyIdentifier does not match the issuer's subjectKeyIdentifier")
	}
	if len(leaf.SubjectKeyId) != 20 {
		t.Error("leaf has no subjectKeyIdentifier; engine.py emitted one, so an imported leaf would drift")
	}
}

// TestCreateCertificateEmitsExactlyOneOfEachExtension proves two things: every
// extension the certificate carries appears exactly once, and the six OIDs a
// fully-specified leaf must have are all present.
//
// It is deliberately NOT a guard against setting one of x509.Certificate's
// convenience fields alongside ExtraExtensions. That cannot produce a duplicate:
// crypto/x509 guards every such field with
// !oidInExtensions(oid, template.ExtraExtensions) (x509.go ~1187-1281), so Go
// silently skips its own copy whenever Extensions() already supplies the OID.
// Setting all four of BasicConstraintsValid, IsCA, KeyUsage and DNSNames was
// verified to leave this test passing.
//
// The hazard a count cannot see is an extension appearing that the template never
// requested. TestCreateCertificateEmitsNothingBeyondTheTemplate covers that.
func TestCreateCertificateEmitsExactlyOneOfEachExtension(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf"}.Expand(),
		SAN:              SAN{DNSNames: []string{"leaf.example"}},
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	counts := map[string]int{}
	for _, ext := range cert.Extensions {
		counts[FormatOID(ext.Id)]++
	}
	for oid, n := range counts {
		if n != 1 {
			t.Errorf("extension %s appears %d times, want exactly 1", oid, n)
		}
	}
	for _, want := range []string{"2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.14", "2.5.29.35"} {
		if counts[want] == 0 {
			t.Errorf("extension %s is missing", want)
		}
	}
}

// TestCreateCertificateHonorsCriticality is the capability hashicorp/tls lacks:
// it hardcodes criticality, so a config that needs a non-critical keyUsage or a
// critical extendedKeyUsage cannot be expressed there.
func TestCreateCertificateHonorsCriticality(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: false},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature"}, Critical: false},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}, Critical: true},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	for oid, wantCritical := range map[string]bool{
		"2.5.29.19": false, // basicConstraints, non-critical by explicit request
		"2.5.29.15": false, // keyUsage, non-critical by explicit request
		"2.5.29.37": true,  // extendedKeyUsage, critical by explicit request
	} {
		parsed, err := ParseOID(oid)
		if err != nil {
			t.Fatalf("ParseOID: %v", err)
		}
		ext, ok := FindExtension(cert.Extensions, parsed)
		if !ok {
			t.Errorf("extension %s is missing", oid)
			continue
		}
		if ext.Critical != wantCritical {
			t.Errorf("extension %s Critical = %v, want %v", oid, ext.Critical, wantCritical)
		}
	}
}

func TestCreateCertificateExtensionOrderIsStable(t *testing.T) {
	t.Parallel()
	// This pins the order Extensions() returns, which is what lets an imported
	// certificate re-encode byte-exact.
	//
	// It is NOT the order an issued certificate carries, and a comparison against
	// a real certificate must match extensions by OID rather than by position.
	// Extensions() yields [2.5.29.19, 2.5.29.15, 2.5.29.37, 2.5.29.17, 2.5.29.30,
	// 2.5.29.14, ...extras], while a CA-signed certificate built from the same
	// template carries [2.5.29.35, 2.5.29.19, ...] because crypto/x509 prepends
	// the authorityKeyIdentifier it derives from the issuer. See
	// CreateCertificate's doc comment for both shapes.
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "cn"}.Expand(),
		SAN:              SAN{DNSNames: []string{"a.example"}},
		Serial:           big.NewInt(1),
		NotBefore:        time.Now(),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
		NameConstraints:  &NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true},
		ExtraExtensions:  []ExtraExtension{{OID: mustOID(t, "1.3.6.1.4.1.99999.1"), Value: []byte{0x05, 0x00}}},
	}
	exts, err := tmpl.Extensions(PublicKeyOf(key))
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	want := []string{
		"2.5.29.19", // basicConstraints
		"2.5.29.15", // keyUsage
		"2.5.29.37", // extendedKeyUsage
		"2.5.29.17", // subjectAltName
		"2.5.29.30", // nameConstraints
		"2.5.29.14", // subjectKeyIdentifier
		"1.3.6.1.4.1.99999.1",
	}
	if len(exts) != len(want) {
		t.Fatalf("Extensions returned %d extensions, want %d", len(exts), len(want))
	}
	for i, oid := range want {
		if got := FormatOID(exts[i].Id); got != oid {
			t.Errorf("extension %d = %s, want %s", i, got, oid)
		}
	}
}

// TestIssuedExtensionOrderMatchesBothDocumentedShapes pins the two orders
// CreateCertificate's doc comment promises, neither of which had a test.
//
// TestCreateCertificateExtensionOrderIsStable pins what Extensions() returns.
// What an *issued* certificate carries is a different list, and it is the one
// that matters: authorityKeyIdentifier comes FIRST for a CA-signed certificate
// (crypto/x509 builds its own extensions ahead of the template's
// ExtraExtensions, and AKI is the only one it still builds here, since Extensions()
// supplies every OID its convenience fields guard), while a self-signed
// certificate has no AKI at all and so carries exactly Extensions()' order.
//
// Both halves are derived from crypto/x509 internals rather than from anything
// this package controls -- x509.go's buildCertExtensions, and the
// bytes.Equal(asn1Issuer, asn1Subject) test that suppresses the AKI. A toolchain
// change to either would otherwise surface as unexplained certificate drift in
// Task 14's comparison and in the golden tests, both of which reason about
// position. It should surface here instead.
func TestIssuedExtensionOrderMatchesBothDocumentedShapes(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "order-ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := PublicKeyOf(key)

	// Every extension kind this package builds, so a reordering anywhere in the
	// list is visible rather than hidden behind a short list.
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "order-probe"}.Expand(),
		SAN:              SAN{DNSNames: []string{"order.example"}},
		Serial:           big.NewInt(0x4001),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign", "crlSign"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
		NameConstraints:  &NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true},
		ExtraExtensions: []ExtraExtension{
			{OID: mustOID(t, "1.3.6.1.4.1.99999.1"), Value: []byte{0x05, 0x00}},
			{OID: mustOID(t, "1.3.6.1.4.1.99999.2"), Value: []byte{0x05, 0x00}},
		},
	}

	exts, err := tmpl.Extensions(pub)
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	fromTemplate := extensionOIDs(exts)

	// The template's own order is pinned absolutely here as well as compared
	// against below. Comparing an issued certificate only against a freshly
	// computed Extensions() would let a reordering *inside* Extensions() move both
	// sides together and stay green: verified by swapping basicConstraints and
	// keyUsage there, which this list catches and the comparisons alone do not.
	wantFromTemplate := []string{
		"2.5.29.19", // basicConstraints
		"2.5.29.15", // keyUsage
		"2.5.29.37", // extendedKeyUsage
		"2.5.29.17", // subjectAltName
		"2.5.29.30", // nameConstraints
		"2.5.29.14", // subjectKeyIdentifier
		"1.3.6.1.4.1.99999.1",
		"1.3.6.1.4.1.99999.2",
	}
	if !slices.Equal(fromTemplate, wantFromTemplate) {
		t.Fatalf("Extensions() order = %v,\n                 want %v", fromTemplate, wantFromTemplate)
	}

	// Half one: CA-signed. authorityKeyIdentifier first, then Extensions()' list
	// verbatim.
	caSignedPEM, err := CreateCertificate(tmpl, pub, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate (CA-signed): %v", err)
	}
	caSigned, err := ParseCertificatePEM(caSignedPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM (CA-signed): %v", err)
	}
	wantCASigned := append([]string{FormatOID(oidAuthorityKeyID)}, fromTemplate...)
	if got := extensionOIDs(caSigned.Extensions); !slices.Equal(got, wantCASigned) {
		t.Errorf("CA-signed extension order = %v,\n                        want %v", got, wantCASigned)
	}

	// Half two: self-signed. No authorityKeyIdentifier, so exactly Extensions()'
	// list.
	selfSignedPEM, err := CreateCertificate(tmpl, pub, nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate (self-signed): %v", err)
	}
	selfSigned, err := ParseCertificatePEM(selfSignedPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM (self-signed): %v", err)
	}
	if got := extensionOIDs(selfSigned.Extensions); !slices.Equal(got, fromTemplate) {
		t.Errorf("self-signed extension order = %v,\n                          want %v", got, fromTemplate)
	}
	if _, ok := FindExtension(selfSigned.Extensions, oidAuthorityKeyID); ok {
		t.Error("self-signed certificate carries an authorityKeyIdentifier; crypto/x509 omits it when issuer and subject DNs are equal, and the documented order depends on that")
	}
}

// extensionOIDs renders an extension list as dotted OIDs, in order.
func extensionOIDs(exts []pkix.Extension) []string {
	oids := make([]string, 0, len(exts))
	for _, ext := range exts {
		oids = append(oids, FormatOID(ext.Id))
	}
	return oids
}

func TestCreateCertificateRejectsBadTemplates(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := PublicKeyOf(key)
	base := func() CertTemplate {
		return CertTemplate{
			Subject:   NamedSubject{CommonName: "cn"}.Expand(),
			Serial:    big.NewInt(1),
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}
	}
	cases := map[string]func(CertTemplate) CertTemplate{
		"nil serial":            func(c CertTemplate) CertTemplate { c.Serial = nil; return c },
		"negative serial":       func(c CertTemplate) CertTemplate { c.Serial = big.NewInt(-1); return c },
		"zero notBefore":        func(c CertTemplate) CertTemplate { c.NotBefore = time.Time{}; return c },
		"zero notAfter":         func(c CertTemplate) CertTemplate { c.NotAfter = time.Time{}; return c },
		"notAfter before":       func(c CertTemplate) CertTemplate { c.NotAfter = c.NotBefore.Add(-time.Hour); return c },
		"empty subject and san": func(c CertTemplate) CertTemplate { c.Subject = Subject{}; c.SAN = SAN{}; return c },
	}
	for label, mutate := range cases {
		if _, err := CreateCertificate(mutate(base()), pub, ca, caKey); err == nil {
			t.Errorf("CreateCertificate(%s) returned nil error, want an error", label)
		}
	}
}

// TestCreateCertificateWithEmptySubjectForcesCriticalSAN ties Task 7's rule into
// issuance: a certificate with no DN must carry a critical SAN or it identifies
// nothing (RFC 5280 4.2.1.6).
func TestCreateCertificateWithEmptySubjectForcesCriticalSAN(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		SAN:       SAN{DNSNames: []string{"only-a-san.example"}, Critical: false},
		Serial:    big.NewInt(1),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	ext, ok := FindExtension(cert.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("no subjectAltName extension")
	}
	if !ext.Critical {
		t.Fatal("SAN is not critical on a certificate with an empty subject")
	}
}

func TestDefaultSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		params KeyParams
		want   x509.SignatureAlgorithm
	}{
		{KeyParams{Algorithm: AlgorithmRSA}, x509.SHA256WithRSA},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P256"}, x509.ECDSAWithSHA256},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P384"}, x509.ECDSAWithSHA384},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P521"}, x509.ECDSAWithSHA512},
		{KeyParams{Algorithm: AlgorithmED25519}, x509.PureEd25519},
	} {
		k, err := GenerateKey(tc.params)
		if err != nil {
			t.Fatalf("GenerateKey(%+v): %v", tc.params, err)
		}
		got, err := DefaultSignatureAlgorithm(k)
		if err != nil {
			t.Errorf("DefaultSignatureAlgorithm(%+v): %v", tc.params, err)
			continue
		}
		if got != tc.want {
			t.Errorf("DefaultSignatureAlgorithm(%+v) = %v, want %v", tc.params, got, tc.want)
		}
	}
}

// TestCreateCertificateRejectsMismatchedSignatureAlgorithm catches the config
// error of asking for an RSA signature algorithm with an ECDSA CA key, which
// Go would otherwise report as an opaque failure deep inside CreateCertificate.
func TestCreateCertificateRejectsMismatchedSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca") // ECDSA by default in testCA
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = CreateCertificate(CertTemplate{
		Subject:            NamedSubject{CommonName: "cn"}.Expand(),
		Serial:             big.NewInt(1),
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, PublicKeyOf(key), ca, caKey)
	if err == nil {
		t.Fatal("CreateCertificate accepted an RSA signature algorithm with an ECDSA signing key")
	}
}

// TestRequestedSignatureAlgorithmIsHonored covers the one branch of
// resolveSignatureAlgorithm nothing else reached: `return requested, nil`.
// Replacing that line with `return DefaultSignatureAlgorithm(signerKey)` left the
// entire suite green, even though signature_algorithm is a user-facing attribute
// on four provider resources -- an input that is silently ignored is exactly the
// class of failure the rest of this file exists to rule out.
//
// Every algorithm here is compatible with its signing key and is deliberately
// NOT that key's default: testCA's P-256 key defaults to ECDSA-SHA256, so only
// honouring the request can produce SHA-384 or SHA-512. The default is asserted
// alongside, so "honoured" is measured against something.
func TestRequestedSignatureAlgorithmIsHonored(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca") // ECDSA P-256
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	issue := func(alg x509.SignatureAlgorithm) *x509.Certificate {
		t.Helper()
		certPEM, err := CreateCertificate(CertTemplate{
			Subject:            NamedSubject{CommonName: "cn"}.Expand(),
			Serial:             big.NewInt(1),
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(time.Hour),
			SignatureAlgorithm: alg,
		}, PublicKeyOf(key), ca, caKey)
		if err != nil {
			t.Fatalf("CreateCertificate(%v): %v", alg, err)
		}
		cert, err := ParseCertificatePEM(certPEM)
		if err != nil {
			t.Fatalf("ParseCertificatePEM: %v", err)
		}
		return cert
	}

	if got := issue(x509.UnknownSignatureAlgorithm).SignatureAlgorithm; got != x509.ECDSAWithSHA256 {
		t.Errorf("unrequested algorithm = %v, want the P-256 default ECDSA-SHA256", got)
	}
	for _, want := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA384, x509.ECDSAWithSHA512} {
		cert := issue(want)
		if cert.SignatureAlgorithm != want {
			t.Errorf("issued certificate is signed with %v, want the requested %v", cert.SignatureAlgorithm, want)
		}
		// The algorithm identifier must describe the signature that is actually
		// there, not just appear in the certificate.
		if err := cert.CheckSignatureFrom(ca); err != nil {
			t.Errorf("certificate requesting %v does not verify against its CA: %v", want, err)
		}
	}

	// The CSR path resolves the algorithm through the same function and is
	// reached by a separate provider resource, so it gets its own assertion.
	csrPEM, err := CreateCertRequest(key, CertRequestTemplate{
		Subject:            NamedSubject{CommonName: "cn"}.Expand(),
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}
	// ParseCertRequestPEM verifies the self-signature, so a request whose
	// algorithm identifier disagreed with its signature would not get this far.
	csr, err := ParseCertRequestPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCertRequestPEM: %v", err)
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("certificate request is signed with %v, want the requested ECDSA-SHA384", csr.SignatureAlgorithm)
	}
}

func TestParseCertificateChainPEM(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	inter, _ := testCA(t, root, rootKey, "intermediate")
	chain := append(EncodeCertificatePEM(inter.Raw), EncodeCertificatePEM(root.Raw)...)

	got, err := ParseCertificateChainPEM(chain)
	if err != nil {
		t.Fatalf("ParseCertificateChainPEM: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d certificates, want 2", len(got))
	}
	if !bytes.Equal(got[0].Raw, inter.Raw) || !bytes.Equal(got[1].Raw, root.Raw) {
		t.Error("chain order was not preserved; leaf-adjacent must come first")
	}
	for label, in := range map[string][]byte{
		"empty":   nil,
		"not pem": []byte("hello"),
	} {
		if _, err := ParseCertificateChainPEM(in); err == nil {
			t.Errorf("ParseCertificateChainPEM(%s) returned nil error, want an error", label)
		}
	}
	keyPEM, err := EncodePrivateKeyPEM(rootKey)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	if _, err := ParseCertificateChainPEM(append(append([]byte(nil), chain...), keyPEM...)); err == nil {
		t.Error("ParseCertificateChainPEM accepted a chain containing a private key block")
	}
}

// TestParseCertificateChainPEMRejectsUndecodablePEM covers the blocks pem.Decode
// reports by saying nothing.
//
// pem.Decode skips a malformed or truncated block and returns the next
// well-formed one, so a chain with a corrupt certificate in it used to parse as
// its intact certificates alone. Nothing told the caller a certificate had been
// dropped. That is survivable while every consumer re-encodes from the parsed
// certificates, and silently wrong the moment one stores the input bytes.
//
// The check is a count of "-----BEGIN " markers against the number of blocks
// decoded, which is why the cases below are built by damaging the base64 body
// rather than by removing the BEGIN line: a chain that opens three blocks and
// yields two is the shape being rejected.
func TestParseCertificateChainPEMRejectsUndecodablePEM(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	inter, _ := testCA(t, root, rootKey, "intermediate")
	interPEM := EncodeCertificatePEM(inter.Raw)
	rootPEM := EncodeCertificatePEM(root.Raw)

	// A block whose body is not valid base64 at all, so pem.Decode cannot make a
	// block of it.
	corrupt := []byte("-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n")
	// A block with no END line, which is what a truncated file looks like.
	truncated := interPEM[:len(interPEM)-40]

	for label, in := range map[string][]byte{
		"corrupt block after the chain":   concat(interPEM, rootPEM, corrupt),
		"corrupt block before the chain":  concat(corrupt, interPEM, rootPEM),
		"corrupt block inside the chain":  concat(interPEM, corrupt, rootPEM),
		"truncated block after the chain": concat(interPEM, rootPEM, truncated),
	} {
		certs, err := ParseCertificateChainPEM(in)
		if err == nil {
			t.Errorf("ParseCertificateChainPEM(%s) returned %d certificates and no error; the undecodable block was dropped silently",
				label, len(certs))
		}
	}

	// A chain whose ONLY block is corrupt. The mixed cases above all decode at
	// least one certificate, so they exercise the markers != len(certs) branch.
	// This one decodes zero, which is the case that used to fall through to the
	// "no CERTIFICATE PEM blocks found" message -- a true claim about pem.Decode's
	// output and a misleading one about the file, which held a block that was
	// dropped. The marker count runs before the empty-chain check precisely so
	// this reports the corruption instead.
	for label, in := range map[string][]byte{
		"corrupt block only":      corrupt,
		"truncated block only":    truncated,
		"two corrupt blocks only": concat(corrupt, truncated),
	} {
		certs, err := ParseCertificateChainPEM(in)
		if err == nil {
			t.Fatalf("ParseCertificateChainPEM(%s) returned %d certificates and no error", label, len(certs))
		}
		if !strings.Contains(err.Error(), "decoded") {
			t.Errorf("ParseCertificateChainPEM(%s) error = %q; a corrupt-only chain must report that a block opened but did not decode, not that no block was found", label, err)
		}
	}

	// Non-PEM text is NOT an error, wherever it appears. Real chain files carry
	// it: see the doc comment on ParseCertificateChainPEM, and
	// TestParseCertificateChainPEMReadsAnOpenSSLEmittedChain for the generated
	// article.
	for label, in := range map[string][]byte{
		"text before":  concat([]byte("# homelab chain\n"), interPEM, rootPEM),
		"text between": concat(interPEM, []byte("subject=CN = root\nissuer=CN = root\n"), rootPEM),
		"text after":   concat(interPEM, rootPEM, []byte("\nGenerated by hand.\n")),
		"blank lines":  concat(interPEM, []byte("\n\n"), rootPEM, []byte("\n")),
	} {
		got, err := ParseCertificateChainPEM(in)
		if err != nil {
			t.Errorf("ParseCertificateChainPEM(%s): %v", label, err)
			continue
		}
		if len(got) != 2 {
			t.Errorf("ParseCertificateChainPEM(%s) returned %d certificates, want 2", label, len(got))
		}
	}
}

// TestParseCertificateChainPEMReadsAnOpenSSLEmittedChain is the guard on the
// decision above, made against the real article rather than a hand-written
// imitation.
//
// `openssl crl2pkcs7 -nocrl -certfile chain.pem | openssl pkcs7 -print_certs` is
// the standard way to normalize a chain, and openssl 3.5.7 emits "subject=" and
// "issuer=" lines before every block. A parser that rejected non-PEM text between
// blocks -- the obvious way to reject trailing junk -- would reject that file,
// and with it `openssl s_client -showcerts` output and most distribution CA
// bundles.
func TestParseCertificateChainPEMReadsAnOpenSSLEmittedChain(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	root, rootKey := testCA(t, nil, nil, "openssl-root")
	inter, _ := testCA(t, root, rootKey, "openssl-intermediate")
	chain := concat(EncodeCertificatePEM(inter.Raw), EncodeCertificatePEM(root.Raw))

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chainPath, chain, 0o600); err != nil {
		t.Fatalf("writing the chain: %v", err)
	}
	p7 := opensslRun(t, nil, "crl2pkcs7", "-nocrl", "-certfile", chainPath)
	printed := []byte(opensslRun(t, []byte(p7), "pkcs7", "-print_certs"))

	// The fixture has to actually carry the metadata, or this test proves nothing.
	if !bytes.Contains(printed, []byte("subject=")) {
		t.Fatalf("openssl pkcs7 -print_certs emitted no subject= lines, so this fixture does not exercise the interleaved-text case:\n%s", printed)
	}

	got, err := ParseCertificateChainPEM(printed)
	if err != nil {
		t.Fatalf("ParseCertificateChainPEM(openssl-emitted chain): %v\n%s", err, printed)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d certificates from the openssl-emitted chain, want 2", len(got))
	}
	if !bytes.Equal(got[0].Raw, inter.Raw) || !bytes.Equal(got[1].Raw, root.Raw) {
		t.Error("openssl-emitted chain did not round-trip to the same two certificates in the same order")
	}
}

// concat joins byte slices without aliasing any of them, which append-based
// concatenation of a PEM block would risk doing.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// --- Coverage added during implementation -----------------------------------
//
// The tests below close gaps the brief's cases leave open. Each one fails if a
// specific plausible mistake is made, and none of the tests above notices that
// mistake.

// TestCreateCertificateSubjectKeyIDIsTheSubjectsKey pins that the
// subjectKeyIdentifier is computed over the certificate's own public key rather
// than the signing key's.
//
// Nothing above would catch that confusion. The chain test only checks that the
// leaf's identifier is 20 bytes long, and the issuer's identifier is also 20
// bytes -- so a leaf that advertised its issuer's key identifier as its own
// would still parse, still chain, and still pass every length check, while
// colliding with its issuer and breaking any path building that keys on the
// identifier.
//
// The identifier's *value* is cross-validated against openssl's
// `subjectKeyIdentifier = hash` in TestSubjectKeyIDMatchesOpenSSLHash; what is
// pinned here is that issuance feeds that computation the right key.
func TestCreateCertificateSubjectKeyIDIsTheSubjectsKey(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:   NamedSubject{CommonName: "leaf"}.Expand(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	want := keyIDOf(t, PublicKeyOf(leafKey))
	if !bytes.Equal(leaf.SubjectKeyId, want) {
		t.Errorf("leaf subjectKeyIdentifier = % x, want the SHA-1 of its own key % x", leaf.SubjectKeyId, want)
	}
	if bytes.Equal(leaf.SubjectKeyId, ca.SubjectKeyId) {
		t.Error("leaf subjectKeyIdentifier equals its issuer's; it was computed over the signing key")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, keyIDOf(t, ca.PublicKey)) {
		t.Errorf("leaf authorityKeyIdentifier = % x, want the SHA-1 of the issuer's key % x",
			leaf.AuthorityKeyId, keyIDOf(t, ca.PublicKey))
	}
}

// TestCreateCertificateEmitsNothingBeyondTheTemplate is the test that actually
// enforces "set none of x509.Certificate's convenience fields".
//
// TestCreateCertificateEmitsExactlyOneOfEachExtension does not, despite being
// written for it. crypto/x509 guards every convenience field with
// !oidInExtensions(oid, template.ExtraExtensions), so while this package always
// supplies basicConstraints, keyUsage, extendedKeyUsage, subjectAltName and
// nameConstraints through Extensions(), Go silently skips its own copy and the
// duplicate the count test looks for can never appear. Setting
// BasicConstraintsValid, IsCA, KeyUsage and DNSNames on the template alongside
// the extension list was verified to leave the whole suite passing.
//
// The real damage from a convenience field is not a duplicate but an *extra*
// extension: a field set unconditionally emits its extension even when the
// template asked for none, so a leaf whose config carries no basic_constraints
// block would still get basicConstraints, and would then differ from the adopted
// certificate it is supposed to match. Counting occurrences cannot see that;
// comparing the full OID set can.
//
// authorityKeyIdentifier is the one addition Go is expected to make, since it
// comes from the issuer rather than the template.
func TestCreateCertificateEmitsNothingBeyondTheTemplate(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := PublicKeyOf(key)

	// A deliberately bare template: no extension block of any kind is requested,
	// so Extensions() yields subjectKeyIdentifier alone and every convenience
	// field Go might act on is left at its zero value.
	tmpl := CertTemplate{
		Subject:   NamedSubject{CommonName: "bare"}.Expand(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	certPEM, err := CreateCertificate(tmpl, pub, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	wantExts, err := tmpl.Extensions(pub)
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	want := map[string]bool{FormatOID(oidAuthorityKeyID): true}
	for _, ext := range wantExts {
		want[FormatOID(ext.Id)] = true
	}
	for _, ext := range cert.Extensions {
		if !want[FormatOID(ext.Id)] {
			t.Errorf("certificate carries extension %s, which the template never asked for; a convenience field on the x509.Certificate template is set", FormatOID(ext.Id))
		}
	}
	if len(cert.Extensions) != len(want) {
		t.Errorf("certificate carries %d extensions, want %d (%d from the template plus authorityKeyIdentifier)",
			len(cert.Extensions), len(want), len(wantExts))
	}
}

// TestCertTemplateExtensionsRejectsDuplicateOID covers the duplicate-OID guard.
// Without a test, an extra_extension block whose OID collides with a managed
// extension would silently produce a certificate carrying that OID twice, which
// is exactly what TestCreateCertificateEmitsExactlyOneOfEachExtension exists to
// prevent -- but that test never supplies a colliding extra extension, so it
// would pass.
func TestCertTemplateExtensionsRejectsDuplicateOID(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := PublicKeyOf(key)
	base := CertTemplate{
		Subject:   NamedSubject{CommonName: "cn"}.Expand(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	for label, extras := range map[string][]ExtraExtension{
		"collides with keyUsage": {
			{OID: mustOID(t, "2.5.29.15"), Value: []byte{0x03, 0x02, 0x07, 0x80}},
		},
		"collides with subjectKeyIdentifier": {
			{OID: mustOID(t, "2.5.29.14"), Value: []byte{0x04, 0x01, 0x00}},
		},
		"two extras collide with each other": {
			{OID: mustOID(t, "1.3.6.1.4.1.99999.7"), Value: []byte{0x05, 0x00}},
			{OID: mustOID(t, "1.3.6.1.4.1.99999.7"), Value: []byte{0x05, 0x00}},
		},
	} {
		tmpl := base
		tmpl.KeyUsage = &KeyUsage{Usages: []string{"digitalSignature"}, Critical: true}
		tmpl.ExtraExtensions = extras

		if _, err := tmpl.Extensions(pub); err == nil {
			t.Errorf("Extensions(%s) returned nil error, want a duplicate-OID error", label)
		}
		// The same rejection must reach the issuance path, since that is where a
		// duplicate would otherwise become a certificate.
		if _, err := CreateCertificate(tmpl, pub, nil, key); err == nil {
			t.Errorf("CreateCertificate(%s) returned nil error, want a duplicate-OID error", label)
		}
	}
}

// TestCreateCertificateRejectsZeroSerial covers the serial value the brief's
// table omits. RFC 5280 4.1.2.2 requires a positive serial, but
// x509.CreateCertificate only rejects a negative one, so a zero serial would be
// issued happily by Go and no case above would notice.
func TestCreateCertificateRejectsZeroSerial(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := CreateCertificate(CertTemplate{
		Subject:   NamedSubject{CommonName: "cn"}.Expand(),
		Serial:    big.NewInt(0),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(key), ca, caKey); err == nil {
		t.Error("CreateCertificate accepted a zero serial number")
	}
}

// TestParseCertificatePEMRejectsBadInput gives the single-certificate parser the
// negative coverage ParseCertificateChainPEM already has. The private-key case
// is the one that matters: this parser feeds certificate_pem attributes, and a
// PEM block accepted here for its bytes rather than its type is the same class
// of leak the chain parser is guarded against.
func TestParseCertificatePEMRejectsBadInput(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	keyPEM, err := EncodePrivateKeyPEM(rootKey)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	certPEM := EncodeCertificatePEM(root.Raw)

	for label, in := range map[string][]byte{
		"empty":         nil,
		"not pem":       []byte("hello"),
		"private key":   keyPEM,
		"two certs":     append(append([]byte(nil), certPEM...), certPEM...),
		"malformed der": EncodeCertificatePEM([]byte{0x30, 0x03, 0x02, 0x01, 0x01}),
	} {
		if _, err := ParseCertificatePEM(in); err == nil {
			t.Errorf("ParseCertificatePEM(%s) returned nil error, want an error", label)
		}
	}

	// The valid case must still round-trip, so the checks above cannot pass by
	// rejecting everything.
	if _, err := ParseCertificatePEM(certPEM); err != nil {
		t.Errorf("ParseCertificatePEM(a valid certificate): %v", err)
	}
}

// TestDecodeSinglePEMBlockRejectsUndecodablePEM is
// TestParseCertificateChainPEMRejectsUndecodablePEM for the single-block parsers,
// and it exists because decodeSinglePEMBlock had the same property the chain
// parser was just fixed for: pem.Decode skips a malformed or truncated block, so a
// "-----BEGIN " marker that did not decode was indistinguishable from one that was
// never there.
//
// The two shapes below were both silently wrong, in different ways. A corrupt
// block followed by an intact one parsed as the intact one alone -- no error, one
// certificate, and no indication that the file held two. A corrupt block on its
// own reported "no PEM block found", which is true of pem.Decode's return value
// and false of the file, and sends the operator looking for a missing attribute
// rather than a damaged one.
//
// Both parsers are exercised, because the fix is in the shared helper and a
// regression could be reintroduced in either caller's path.
func TestDecodeSinglePEMBlockRejectsUndecodablePEM(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	certPEM := EncodeCertificatePEM(root.Raw)
	csrPEM, err := CreateCertRequest(rootKey, CertRequestTemplate{
		Subject: NamedSubject{CommonName: "cn"}.Expand(),
	})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}

	// A block whose body is not valid base64 at all, and a block with no END line,
	// which is what a truncated file looks like. Built by damaging the body rather
	// than by removing the BEGIN line, because "opens a block and yields none" is
	// the shape being rejected.
	corrupt := []byte("-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n")
	truncatedCert := certPEM[:len(certPEM)-40]

	for label, in := range map[string][]byte{
		"corrupt block alone":             corrupt,
		"corrupt block before the cert":   concat(corrupt, certPEM),
		"corrupt block after the cert":    concat(certPEM, corrupt),
		"truncated block after the cert":  concat(certPEM, truncatedCert),
		"truncated block before the cert": concat(truncatedCert, certPEM),
	} {
		cert, err := ParseCertificatePEM(in)
		if err == nil {
			t.Errorf("ParseCertificatePEM(%s) returned a certificate (%s) and no error; the undecodable block was dropped silently",
				label, cert.Subject.CommonName)
		}
	}
	if _, err := ParseCertRequestPEM(concat(csrPEM, corrupt)); err == nil {
		t.Error("ParseCertRequestPEM(corrupt block after the request) returned nil error; the undecodable block was dropped silently")
	}

	// A file holding nothing but a corrupt block errored before this change too --
	// pem.Decode returns nil and the old code said "no PEM block found" -- so
	// error-ness alone does not distinguish the fix. The message is what does: the
	// file plainly contains a BEGIN marker, and telling the operator there is no
	// PEM in it sends them looking for a missing attribute instead of a damaged
	// one.
	_, err = ParseCertificatePEM(corrupt)
	if err == nil {
		t.Fatal("ParseCertificatePEM(corrupt block alone) returned nil error")
	}
	if strings.Contains(err.Error(), "no PEM block found") {
		t.Errorf("ParseCertificatePEM(corrupt block alone) error = %q, want it to say the block did not decode rather than that there was none", err)
	}

	// A file with no marker at all still reports the plain message, because "you
	// gave me no PEM" and "you gave me PEM I could not read" are different
	// problems and lead an operator to look in different places.
	_, err = ParseCertificatePEM([]byte("subject=CN = root\n"))
	if err == nil {
		t.Fatal("ParseCertificatePEM(no PEM at all) returned nil error")
	}
	if !strings.Contains(err.Error(), "no PEM block found") {
		t.Errorf("ParseCertificatePEM(no PEM at all) error = %q, want the no-block message rather than an undecodable-block one", err)
	}

	// Non-PEM text is NOT an error, wherever it appears -- unchanged from before
	// the fix, and the constraint the marker count had to be designed around. See
	// TestDecodeSinglePEMBlockReadsAnOpenSSLEmittedCertificate for the generated
	// article.
	for label, in := range map[string][]byte{
		"text before":       concat([]byte("# homelab root\n"), certPEM),
		"text after":        concat(certPEM, []byte("\nGenerated by hand.\n")),
		"text either side":  concat([]byte("subject=CN = root\n"), certPEM, []byte("issuer=CN = root\n")),
		"surrounding blank": concat([]byte("\n\n"), certPEM, []byte("\n")),
	} {
		got, err := ParseCertificatePEM(in)
		if err != nil {
			t.Errorf("ParseCertificatePEM(%s): %v", label, err)
			continue
		}
		if !bytes.Equal(got.Raw, root.Raw) {
			t.Errorf("ParseCertificatePEM(%s) returned a different certificate", label)
		}
	}
}

// TestDecodeSinglePEMBlockReadsAnOpenSSLEmittedCertificate is the guard on the
// interleaved-text decision, made against the real article rather than a
// hand-written imitation, and the single-certificate counterpart of
// TestParseCertificateChainPEMReadsAnOpenSSLEmittedChain.
//
// openssl 3.5.7 prefixes even a one-certificate `pkcs7 -print_certs` with
// "subject=" and "issuer=" lines, and `openssl x509 -text` puts a whole
// certificate dump ahead of the block. Both are realistic things to paste into a
// certificate_pem attribute, and a marker count implemented as "reject anything
// that is not a PEM block" would reject them.
func TestDecodeSinglePEMBlockReadsAnOpenSSLEmittedCertificate(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	root, _ := testCA(t, nil, nil, "openssl-single")
	certPEM := EncodeCertificatePEM(root.Raw)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	p7 := opensslRun(t, nil, "crl2pkcs7", "-nocrl", "-certfile", certPath)

	for label, emitted := range map[string][]byte{
		"pkcs7 -print_certs": []byte(opensslRun(t, []byte(p7), "pkcs7", "-print_certs")),
		"x509 -text":         []byte(opensslRun(t, certPEM, "x509", "-text", "-nameopt", "oneline")),
	} {
		// Each fixture has to actually carry non-PEM text, or this test proves
		// nothing about the decision it is guarding.
		if !bytes.Contains(emitted, []byte("subject")) && !bytes.Contains(emitted, []byte("Subject")) {
			t.Fatalf("openssl %s emitted no subject line, so this fixture does not exercise the interleaved-text case:\n%s", label, emitted)
		}
		if n := bytes.Count(emitted, []byte(pemBeginMarker)); n != 1 {
			t.Fatalf("openssl %s emitted %d BEGIN markers, want 1; this fixture is not the single-block case:\n%s", label, n, emitted)
		}
		got, err := ParseCertificatePEM(emitted)
		if err != nil {
			t.Errorf("ParseCertificatePEM(openssl %s output): %v\n%s", label, err, emitted)
			continue
		}
		if !bytes.Equal(got.Raw, root.Raw) {
			t.Errorf("openssl %s output did not round-trip to the same certificate", label)
		}
	}
}

// TestCreateCertRequestRejectsMismatchedSignatureAlgorithm is the CSR-side twin
// of TestCreateCertificateRejectsMismatchedSignatureAlgorithm. The mismatch is
// the same config error and deserves the same clear message, and CSR creation is
// a separate code path that would otherwise surface Go's opaque one.
func TestCreateCertRequestRejectsMismatchedSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmED25519})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := CreateCertRequest(key, CertRequestTemplate{
		Subject:            NamedSubject{CommonName: "cn"}.Expand(),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}); err == nil {
		t.Fatal("CreateCertRequest accepted an ECDSA signature algorithm with an Ed25519 key")
	}
}

// TestCreateCertificateRejectsInsecureSignatureAlgorithms pins that a SHA-1 or
// MD5 algorithm is refused at issuance even though the signing key is the right
// family for it, so the family check alone cannot wave it through.
//
// The failure this prevents is a certificate the library cannot verify: Go signs
// a SHA-1 or MD5 request without complaint, and its own CheckSignature then
// rejects the result with InsecureAlgorithmError. oids.go omits these algorithms
// from the provider's vocabulary for exactly that reason, and this package is a
// public API surface in its own right rather than something only reachable
// through the schema.
func TestCreateCertificateRejectsInsecureSignatureAlgorithms(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca") // ECDSA P-256
	rsaCA, rsaCAKey := testRSACA(t, "rsa-ca")

	for _, tc := range []struct {
		name   string
		alg    x509.SignatureAlgorithm
		parent *x509.Certificate
		signer crypto.Signer
	}{
		// Each case pairs the algorithm with a signing key of the family it
		// requires, so only the allow-list can reject it.
		{"SHA1WithRSA", x509.SHA1WithRSA, rsaCA, rsaCAKey},
		{"MD5WithRSA", x509.MD5WithRSA, rsaCA, rsaCAKey},
		{"ECDSAWithSHA1", x509.ECDSAWithSHA1, ca, caKey},
	} {
		key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if _, err := CreateCertificate(CertTemplate{
			Subject:            NamedSubject{CommonName: "cn"}.Expand(),
			Serial:             big.NewInt(1),
			NotBefore:          time.Now(),
			NotAfter:           time.Now().Add(time.Hour),
			SignatureAlgorithm: tc.alg,
		}, PublicKeyOf(key), tc.parent, tc.signer); err == nil {
			t.Errorf("CreateCertificate accepted %s, which this package does not offer", tc.name)
		}
	}
}

// TestSignatureAlgorithmKeyTypesCoversEveryOfferedAlgorithm keeps the allow-list
// and oids.go's vocabulary in step. The map derives its domain from
// signatureAlgorithmValues, so an algorithm added there but left unclassified
// would be silently rejected at issuance rather than reported as a gap.
func TestSignatureAlgorithmKeyTypesCoversEveryOfferedAlgorithm(t *testing.T) {
	t.Parallel()
	for _, name := range SignatureAlgorithmNames() {
		alg, err := SignatureAlgorithmByName(name)
		if err != nil {
			t.Fatalf("SignatureAlgorithmByName(%q): %v", name, err)
		}
		if _, ok := signatureAlgorithmKeyTypes[alg]; !ok {
			t.Errorf("signature algorithm %q (%v) is offered by oids.go but has no key family, so issuance would reject it", name, alg)
		}
	}
	if len(signatureAlgorithmKeyTypes) != len(SignatureAlgorithmNames()) {
		t.Errorf("signatureAlgorithmKeyTypes has %d entries, want %d; the allow-list admits an algorithm oids.go does not offer",
			len(signatureAlgorithmKeyTypes), len(SignatureAlgorithmNames()))
	}
}

// testRSACA issues a self-signed RSA CA, for the cases that need an RSA signing
// key. testCA is ECDSA because RSA generation dominates the suite's runtime.
func testRSACA(t *testing.T, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: cn, Organization: "homelab"}.Expand(),
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(%s): %v", cn, err)
	}
	return cert, key
}

// keyIDOf returns the raw RFC 5280 method 1 key identifier for pub, unwrapped
// from the extension SubjectKeyIDExtension builds.
func keyIDOf(t *testing.T, pub any) []byte {
	t.Helper()
	ext, err := SubjectKeyIDExtension(pub)
	if err != nil {
		t.Fatalf("SubjectKeyIDExtension: %v", err)
	}
	var id []byte
	if _, err := asn1.Unmarshal(ext.Value, &id); err != nil {
		t.Fatalf("unmarshaling subjectKeyIdentifier: %v", err)
	}
	return id
}
