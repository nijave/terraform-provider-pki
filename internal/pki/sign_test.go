// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
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

// TestCreateCertificateEmitsExactlyOneOfEachExtension is the guard against the
// double-emission trap: if a template field were passed to both
// x509.Certificate's convenience field and ExtraExtensions, Go would write the
// extension twice with different criticality and some parsers would take the
// wrong one.
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
	// A stable order is what lets Task 14 compare extension lists positionally
	// and lets an imported certificate re-encode byte-exact.
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
		"empty":        nil,
		"not pem":      []byte("hello"),
		"key in chain": EncodeCertificatePEM(root.Raw),
	} {
		if label == "key in chain" {
			continue // covered below with a real key block
		}
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
