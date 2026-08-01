// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

// desiredFor rebuilds the template that produced a fixture leaf, so a
// comparison against the issued certificate reports no drift.
func desiredFor(t *testing.T, leaf *x509.Certificate) CertTemplate {
	t.Helper()
	subject, err := ParseSubjectDER(leaf.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	sanExt, ok := FindExtension(leaf.Extensions, oidSubjectAltName)
	var san SAN
	if ok {
		san, err = ParseSANExtension(sanExt)
		if err != nil {
			t.Fatalf("ParseSANExtension: %v", err)
		}
		san.Critical = sanExt.Critical
	}
	return CertTemplate{
		Subject:          subject,
		SAN:              san,
		Serial:           leaf.SerialNumber,
		NotBefore:        leaf.NotBefore,
		NotAfter:         leaf.NotAfter,
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}
}

// desiredForCA rebuilds the template testCA issues from, for the tests that need
// a CA certificate as the compared subject rather than a leaf.
func desiredForCA(t *testing.T, ca *x509.Certificate) CertTemplate {
	t.Helper()
	subject, err := ParseSubjectDER(ca.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	return CertTemplate{
		Subject:          subject,
		Serial:           ca.SerialNumber,
		NotBefore:        ca.NotBefore,
		NotAfter:         ca.NotAfter,
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}
}

// driftFields joins a drift slice's fields in reported order, so a test can
// assert on the whole set at once rather than one entry at a time.
func driftFields(drift []Drift) string {
	fields := make([]string, 0, len(drift))
	for _, d := range drift {
		fields = append(fields, d.Field)
	}
	return strings.Join(fields, ",")
}

// selfSign issues tmpl as a self-signed certificate and parses it back.
func selfSign(t *testing.T, tmpl CertTemplate, key crypto.Signer) *x509.Certificate {
	t.Helper()
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return cert
}

// TestCompareCertificateNoDriftOnAnUnchangedCertificate is the property that
// makes the whole design work: reparsing an issued certificate and comparing it
// to the template that produced it must report nothing.
func TestCompareCertificateNoDriftOnAnUnchangedCertificate(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	drift, err := CompareCertificate(CompareInput{
		Desired:          desiredFor(t, leaf),
		DesiredPublicKey: PublicKeyOf(key),
		Actual:           leaf,
		CA:               ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("reported drift on an unchanged certificate: %v", drift)
	}
}

// TestCompareCertificateIgnoresRotatingCAKey is spec section 9's headline
// guarantee and spec section 10's acceptance criterion: re-reading a rotating
// Bitwarden Secret must not trigger a replacement. ca_private_key_pem is not
// derivable from a certificate and therefore is not in CompareInput at all --
// this test documents that absence deliberately.
func TestCompareCertificateIgnoresRotatingCAKey(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)

	// Two comparisons, structurally identical, with nothing about the CA key
	// available to either. If a future refactor adds a key field to
	// CompareInput, this test stops compiling, which is the intent.
	for i := 0; i < 2; i++ {
		drift, err := CompareCertificate(CompareInput{
			Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
		})
		if err != nil {
			t.Fatalf("CompareCertificate: %v", err)
		}
		if len(drift) != 0 {
			t.Fatalf("iteration %d reported drift: %v", i, drift)
		}
	}
}

func TestCompareCertificateDetectsEachKindOfDrift(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	pub := PublicKeyOf(key)

	for label, tc := range map[string]struct {
		mutate    func(CertTemplate) CertTemplate
		wantField string
	}{
		"subject": {
			mutate: func(c CertTemplate) CertTemplate {
				c.Subject = NamedSubject{CommonName: "different"}.Expand()
				return c
			},
			wantField: "subject",
		},
		"san": {
			mutate:    func(c CertTemplate) CertTemplate { c.SAN = SAN{DNSNames: []string{"other.example"}}; return c },
			wantField: "san",
		},
		"serial": {
			mutate:    func(c CertTemplate) CertTemplate { c.Serial = big.NewInt(0x9999); return c },
			wantField: "serial_number",
		},
		"notAfter": {
			mutate:    func(c CertTemplate) CertTemplate { c.NotAfter = c.NotAfter.Add(24 * time.Hour); return c },
			wantField: "not_after",
		},
		"notBefore": {
			mutate:    func(c CertTemplate) CertTemplate { c.NotBefore = c.NotBefore.Add(-24 * time.Hour); return c },
			wantField: "not_before",
		},
		"key usage bits": {
			mutate: func(c CertTemplate) CertTemplate {
				c.KeyUsage = &KeyUsage{Usages: []string{"digitalSignature"}, Critical: true}
				return c
			},
			wantField: "2.5.29.15",
		},
		"key usage criticality": {
			mutate: func(c CertTemplate) CertTemplate {
				c.KeyUsage = &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: false}
				return c
			},
			wantField: "2.5.29.15",
		},
		"extended key usage": {
			mutate: func(c CertTemplate) CertTemplate {
				c.ExtKeyUsage = &ExtKeyUsage{Usages: []string{"serverAuth"}}
				return c
			},
			wantField: "2.5.29.37",
		},
		"basic constraints ca flag": {
			mutate: func(c CertTemplate) CertTemplate {
				c.BasicConstraints = &BasicConstraints{CA: true, Critical: true}
				return c
			},
			wantField: "2.5.29.19",
		},
		"added extension": {
			mutate: func(c CertTemplate) CertTemplate {
				c.ExtraExtensions = []ExtraExtension{{OID: mustOID(t, "1.3.6.1.4.1.99999.1"), Value: []byte{0x05, 0x00}}}
				return c
			},
			wantField: "1.3.6.1.4.1.99999.1",
		},
		"removed extension": {
			mutate:    func(c CertTemplate) CertTemplate { c.ExtKeyUsage = nil; return c },
			wantField: "2.5.29.37",
		},
	} {
		drift, err := CompareCertificate(CompareInput{
			Desired: tc.mutate(desiredFor(t, leaf)), DesiredPublicKey: pub, Actual: leaf, CA: ca,
		})
		if err != nil {
			t.Errorf("%s: CompareCertificate: %v", label, err)
			continue
		}
		if len(drift) == 0 {
			t.Errorf("%s: reported no drift, want drift on %q", label, tc.wantField)
			continue
		}
		found := false
		for _, d := range drift {
			if d.Field == tc.wantField {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: drift = %v, want an entry for %q", label, drift, tc.wantField)
		}
	}
}

// TestCompareCertificateIgnoresKeyUsageOrder confirms the comparison inherits
// the encoding's insensitivity to config order. Reordering a usages list in HCL
// must not replace a certificate.
func TestCompareCertificateIgnoresKeyUsageOrder(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)
	desired.KeyUsage = &KeyUsage{Usages: []string{"keyEncipherment", "digitalSignature"}, Critical: true}
	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("reordering the key usage list reported drift: %v", drift)
	}
}

// TestCompareCertificateIgnoresNamedVersusOrderedSubjectForm is spec section
// 5.1's requirement: any config that encodes to the same DN plans clean.
func TestCompareCertificateIgnoresNamedVersusOrderedSubjectForm(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	named := NamedSubject{CommonName: "cn", UID: "uid", GivenName: "gn", Surname: "sn", Organization: "o"}.Expand()
	tmpl := CertTemplate{
		Subject:   named,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:  time.Now().Add(time.Hour).Truncate(time.Second),
	}
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// Now compare with the ordered form spelled out attribute by attribute.
	ordered := tmpl
	ordered.Subject = Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "uid", "uid"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	drift, err := CompareCertificate(CompareInput{
		Desired: ordered, DesiredPublicKey: PublicKeyOf(key), Actual: cert, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("the ordered form of the same DN reported drift: %v", drift)
	}
}

// TestCompareCertificateIgnoresSubSecondValidityPrecision covers the truncation
// in the validity comparison, which nothing else here reaches: every other
// fixture takes its timestamps from an already-issued certificate, where they
// have been through DER and are whole seconds already.
//
// DER encodes these timestamps at second granularity, so a template built from
// time.Now -- which every real caller's is -- carries a sub-second component its
// own issued certificate cannot. Comparing the instants directly would report
// drift on a certificate the instant after issuing it.
func TestCompareCertificateIgnoresSubSecondValidityPrecision(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := CertTemplate{
		Subject:   NamedSubject{CommonName: "sub-second"}.Expand(),
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour).Truncate(time.Second).Add(500 * time.Millisecond),
		NotAfter:  time.Now().Add(time.Hour).Truncate(time.Second).Add(500 * time.Millisecond),
	}
	if tmpl.NotBefore.Nanosecond() == 0 || tmpl.NotAfter.Nanosecond() == 0 {
		t.Fatal("the fixture timestamps carry no sub-second component, so this test would prove nothing")
	}
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	drift, err := CompareCertificate(CompareInput{
		Desired: tmpl, DesiredPublicKey: PublicKeyOf(key), Actual: cert, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a template with sub-second timestamps reported drift against its own certificate: %v", drift)
	}
}

func TestCompareCertificateDetectsPublicKeyMismatch(t *testing.T) {
	t.Parallel()
	// A rotated private_key_pem means the certificate no longer matches its
	// key and must be reissued. This is drift the comparison must catch, in
	// contrast to a rotated CA key, which it must ignore.
	leaf, _, ca := testLeaf(t)
	other, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(other), Actual: leaf, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) == 0 {
		t.Fatal("a public key mismatch reported no drift")
	}
	found := false
	for _, d := range drift {
		if d.Field == "public_key" {
			found = true
		}
	}
	if !found {
		t.Errorf("drift = %v, want an entry for \"public_key\"", drift)
	}
}

func TestCompareCertificateDetectsWrongIssuer(t *testing.T) {
	t.Parallel()
	// Spec section 9 compares the issuer DN and the signature against
	// ca_certificate_pem. Pointing a resource at a different CA must reissue.
	leaf, key, _ := testLeaf(t)
	otherCA, _ := testCA(t, nil, nil, "a-different-ca")
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: otherCA,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) == 0 {
		t.Fatal("comparing against a different CA reported no drift")
	}
	found := false
	for _, d := range drift {
		if d.Field == "issuer" || d.Field == "signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("drift = %v, want an entry for \"issuer\" or \"signature\"", drift)
	}
}

// TestCompareCertificateDetectsIssuerDNAloneWhenTheSignatureStillVerifies pins
// the issuer DN comparison on its own. TestCompareCertificateDetectsWrongIssuer
// accepts either "issuer" or "signature", so it would still pass with the
// issuer DN comparison deleted entirely; this one would not.
//
// The trick is a CA certificate carrying the real CA's public key under a
// different subject DN. CheckSignatureFrom never looks at DNs, so the signature
// verifies and only the issuer DN can report the difference.
func TestCompareCertificateDetectsIssuerDNAloneWhenTheSignatureStillVerifies(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	sub, subKey := testCA(t, ca, caKey, "homelab-sub")

	renamedPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "renamed-ca", Organization: "homelab"}.Expand(),
		Serial:           big.NewInt(7),
		NotBefore:        ca.NotBefore,
		NotAfter:         ca.NotAfter,
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}, PublicKeyOf(caKey), nil, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	renamed, err := ParseCertificatePEM(renamedPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	drift, err := CompareCertificate(CompareInput{
		Desired: desiredForCA(t, sub), DesiredPublicKey: PublicKeyOf(subKey), Actual: sub, CA: renamed,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 1 || drift[0].Field != "issuer" {
		t.Fatalf("drift = %v, want exactly one entry for \"issuer\"", drift)
	}
}

// TestCompareCertificateDetectsSignatureAloneWhenTheIssuerDNMatches is the
// mirror image: two roots share a DN, so only the signature check can tell them
// apart. Deleting the signature check would leave this test failing.
func TestCompareCertificateDetectsSignatureAloneWhenTheIssuerDNMatches(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	// testLeaf's CA is CN=homelab-ca,O=homelab; a second one has the same DN
	// and a different key.
	impostor, _ := testCA(t, nil, nil, "homelab-ca")
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: impostor,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 1 || drift[0].Field != "signature" {
		t.Fatalf("drift = %v, want exactly one entry for \"signature\"", drift)
	}
}

func TestCompareCertificateSelfSignedIssuerCheck(t *testing.T) {
	t.Parallel()
	// A self-signed root has no separate CA, so CompareInput.CA is nil and the
	// signature is checked against the certificate itself.
	ca, caKey := testCA(t, nil, nil, "root")
	subject, err := ParseSubjectDER(ca.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	desired := CertTemplate{
		Subject:          subject,
		Serial:           ca.SerialNumber,
		NotBefore:        ca.NotBefore,
		NotAfter:         ca.NotAfter,
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}
	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(caKey), Actual: ca, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a self-signed root reported drift against its own template: %v", drift)
	}
}

// TestCompareCertificateNilCAOnACASignedCertificateIsDrift is what stops
// TestCompareCertificateSelfSignedIssuerCheck from passing vacuously: that test
// asserts no drift, so the nil-CA path could be a no-op and it would still be
// green. A CA-signed leaf compared with no CA is not self-signed on either
// count -- its issuer DN is not its subject DN, and its own key does not verify
// its signature -- and both halves of the nil-CA path have to say so.
func TestCompareCertificateNilCAOnACASignedCertificateIsDrift(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if got := driftFields(drift); got != "issuer,signature" {
		t.Fatalf("drift = %v (fields %q), want entries for \"issuer\" and \"signature\"", drift, got)
	}
}

// TestCompareCertificateSelfSignedNonCAReportsNoDrift covers the first
// non-converging false positive that x509.CheckSignatureFrom would produce.
//
// It enforces RFC 5280's issuer constraints before verifying any cryptography,
// so a self-signed certificate whose basicConstraints says ca = false fails it
// with "parent certificate cannot sign this kind of certificate" -- reported as
// signature drift on a certificate that matches its template byte for byte. The
// replacement would carry the same basicConstraints and drift again on the next
// plan, forever. ca is user-settable per spec section 6.3, so this is reachable
// from ordinary HCL.
func TestCompareCertificateSelfSignedNonCAReportsNoDrift(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "self-signed-non-ca"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:         time.Now().Add(time.Hour).Truncate(time.Second),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
	}
	cert := selfSign(t, tmpl, key)

	drift, err := CompareCertificate(CompareInput{
		Desired: tmpl, DesiredPublicKey: PublicKeyOf(key), Actual: cert, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a self-signed non-CA reported drift against its own template: %v", drift)
	}
}

// TestCompareCertificateSelfSignedCAWithoutKeyCertSignReportsNoDrift covers the
// second one. x509.CheckSignatureFrom also rejects an issuer whose keyUsage
// omits keyCertSign, so a CA configured with only crlSign would drift forever
// against a template it reproduces exactly. key_usage is user-settable per spec
// section 6.3.
func TestCompareCertificateSelfSignedCAWithoutKeyCertSignReportsNoDrift(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "crl-only-ca"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:         time.Now().Add(time.Hour).Truncate(time.Second),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"crlSign"}, Critical: true},
	}
	cert := selfSign(t, tmpl, key)

	drift, err := CompareCertificate(CompareInput{
		Desired: tmpl, DesiredPublicKey: PublicKeyOf(key), Actual: cert, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a CA without keyCertSign reported drift against its own template: %v", drift)
	}
}

// TestCompareCertificateAcceptsASHA1SignedChain is the SHA-1 half of the
// "unverifiable is not drift" requirement, and it lands better than an error:
// after the move off x509.CheckSignatureFrom, an adopted SHA-1 chain reports
// nothing at all.
//
// Certificate.CheckSignature passes allowSHA1 = true to crypto/x509's internal
// checkSignature, while CheckSignatureFrom passes false -- so the same
// certificate that CheckSignatureFrom rejects with
// "x509: cannot verify signature: insecure algorithm SHA1-RSA" verifies cleanly
// through CheckSignature. No drift and no error is the correct outcome, since
// nothing about the certificate's content has changed; forcing even one reissue
// here would be one device re-enrollment for byte-identical content.
//
// sign.go refuses SHA-1 at issuance, so the fixture is built with crypto/x509
// directly.
func TestCompareCertificateAcceptsASHA1SignedChain(t *testing.T) {
	t.Parallel()
	caKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ca := selfSign(t, CertTemplate{
		Subject:          NamedSubject{CommonName: "sha1-era-ca", Organization: "homelab"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:         time.Now().Add(24 * time.Hour).Truncate(time.Second),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}, caKey)

	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	desired := CertTemplate{
		Subject:          NamedSubject{CommonName: "adopted-sha1-leaf"}.Expand(),
		Serial:           big.NewInt(2),
		NotBefore:        time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:         time.Now().Add(24 * time.Hour).Truncate(time.Second),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
	}
	rawSubject, err := desired.Subject.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	exts, err := desired.Extensions(PublicKeyOf(leafKey))
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:       desired.Serial,
		RawSubject:         rawSubject,
		NotBefore:          desired.NotBefore,
		NotAfter:           desired.NotAfter,
		SignatureAlgorithm: x509.SHA1WithRSA,
		ExtraExtensions:    exts,
	}, ca, PublicKeyOf(leafKey), caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if leaf.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("fixture signature algorithm is %v, want %v; this test would prove nothing",
			leaf.SignatureAlgorithm, x509.SHA1WithRSA)
	}

	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(leafKey), Actual: leaf, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate on a SHA-1 chain: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a SHA-1 signed chain reported drift on unchanged content: %v", drift)
	}
}

// TestCompareCertificateReportsAnUnverifiableSignatureAsAnError is the other
// half: a signature whose algorithm crypto/x509 refuses outright is an error,
// not drift, following the same rule an EncodeDER failure gets. Reporting it as
// drift would force a reissue -- one device re-enrollment -- for content that is
// byte-identical.
//
// MD5 is the reachable trigger: checkSignature returns InsecureAlgorithmError
// for it unconditionally, with no allowSHA1-style exemption.
func TestCompareCertificateReportsAnUnverifiableSignatureAsAnError(t *testing.T) {
	t.Parallel()
	// crypto/x509 will not sign with MD5 ("x509: signing with MD5 is not
	// supported"), so the fixture is made by rewriting the signature algorithm
	// OID of a real SHA-256 certificate. sha256WithRSAEncryption
	// (1.2.840.113549.1.1.11) and md5WithRSAEncryption (1.2.840.113549.1.1.4)
	// encode to the same nine bytes but for the last, so the substitution is
	// length-preserving; both copies are rewritten -- the TBSCertificate's and
	// the outer one -- leaving the certificate internally consistent. The
	// signature no longer matches, which is immaterial: MD5 is refused before
	// any hashing happens, and that refusal is the whole subject of this test.
	caKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	desired := CertTemplate{
		Subject:          NamedSubject{CommonName: "md5-era-ca", Organization: "homelab"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:         time.Now().Add(24 * time.Hour).Truncate(time.Second),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}
	certPEM, err := CreateCertificate(desired, PublicKeyOf(caKey), nil, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("pem.Decode returned no block")
	}

	sha256WithRSA := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	md5WithRSA := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04}
	if n := bytes.Count(block.Bytes, sha256WithRSA); n != 2 {
		t.Fatalf("found the sha256WithRSAEncryption OID %d times, want 2; the fixture would prove nothing", n)
	}
	cert, err := x509.ParseCertificate(bytes.ReplaceAll(block.Bytes, sha256WithRSA, md5WithRSA))
	if err != nil {
		t.Fatalf("x509.ParseCertificate of the patched DER: %v", err)
	}
	if cert.SignatureAlgorithm != x509.MD5WithRSA {
		t.Fatalf("fixture signature algorithm is %v, want %v; this test would prove nothing",
			cert.SignatureAlgorithm, x509.MD5WithRSA)
	}

	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(caKey), Actual: cert, CA: nil,
	})
	if err == nil {
		t.Fatalf("an unverifiable signature returned drift %v and a nil error, want an error", drift)
	}
	if len(drift) != 0 {
		t.Errorf("drift = %v, want no drift alongside the error", drift)
	}
	if !strings.Contains(err.Error(), "MD5") {
		t.Errorf("err = %v, want it to name the algorithm that could not be verified", err)
	}
}

func TestCompareCertificateRejectsMissingActual(t *testing.T) {
	t.Parallel()
	if _, err := CompareCertificate(CompareInput{}); err == nil {
		t.Fatal("CompareCertificate with no actual certificate returned nil error, want an error")
	}
}

// TestCompareCertificateRejectsMissingActualWithEverythingElsePresent pins the
// nil-Actual guard on its own.
//
// TestCompareCertificateRejectsMissingActual above passes a wholly zero
// CompareInput, where every precondition is violated at once, so any one of them
// satisfies it: measured by mutation, deleting the Actual guard leaves that test
// green because the nil public key errors instead. Leaving the rest of the input
// valid is what makes the guard the only thing that can produce the error --
// without it this call dereferences nil and panics.
func TestCompareCertificateRejectsMissingActualWithEverythingElsePresent(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	if _, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: nil,
	}); err == nil {
		t.Fatal("CompareCertificate with a nil Actual returned nil error, want an error")
	}
}

// TestCompareCertificateRejectsMissingDesiredSerial covers the third
// precondition. A template with no serial cannot be issued either -- see
// CertTemplate.validate -- so it must not be reported as matching, and
// FormatSerial would dereference nil.
func TestCompareCertificateRejectsMissingDesiredSerial(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)
	desired.Serial = nil
	if _, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
	}); err == nil {
		t.Fatal("CompareCertificate with no desired serial returned nil error, want an error")
	}
}

// TestCompareCertificateRejectsMissingDesiredPublicKey covers the second
// precondition on its own. TestCompareCertificateRejectsMissingActual passes a
// wholly zero CompareInput, so it cannot distinguish which of the two guards
// fired -- an implementation checking only Actual would satisfy it.
func TestCompareCertificateRejectsMissingDesiredPublicKey(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)
	if _, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: nil, Actual: leaf, CA: ca,
	}); err == nil {
		t.Fatal("CompareCertificate with no desired public key returned nil error, want an error")
	}
}

// TestCompareCertificateRejectsAnActualWithNoSerial covers the fourth
// precondition, which no parsed certificate can reach.
//
// x509.ParseCertificate always fills SerialNumber -- cryptobyte reads it into a
// big.Int that is never nil, whatever the DER says -- so this input has to be
// constructed rather than parsed. That is not a contrivance: x509.Certificate has
// exported fields and no constructor, and CompareInput.Actual is an exported field
// of an exported type, so a caller assembling a certificate in code is a supported
// way to call this function and the only way to reach the guard.
//
// The guard earns its place by what happens without it. Serial.Cmp dereferences
// the nil, and a panic inside a Terraform provider is a plugin crash the operator
// cannot attribute to an attribute or a resource. Everything else in the input
// below is valid, so the error can only come from the serial check.
func TestCompareCertificateRejectsAnActualWithNoSerial(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	actual := *leaf
	actual.SerialNumber = nil

	_, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: &actual, CA: ca,
	})
	if err == nil {
		t.Fatal("CompareCertificate with a nil Actual.SerialNumber returned nil error, want an error")
	}
	// Named specifically, because the desired-serial precondition two lines above
	// produces a similar sentence and this test must not be satisfied by it.
	if !strings.Contains(err.Error(), "actual certificate has no serial number") {
		t.Errorf("err = %v, want the actual-serial precondition's own message", err)
	}
}

// TestCompareExtensionsCollapsesADuplicateOIDInBothDirections is the consistency
// property between compareExtensions' two sweeps.
//
// A duplicate extension OID is forbidden by RFC 5280 4.2 and rejected by
// rejectDuplicateExtensionOIDs on everything this package issues, so it can only
// arrive by adoption -- and adoption is the case the whole comparison exists for.
// The forward sweep has always collapsed duplicates, because it indexes actual by
// OID and takes the first occurrence. The reverse sweep iterated actual directly,
// so an OID the template does not name produced one Drift per copy: the same
// field, the same value, twice, in a plan explanation where an operator counts
// lines to decide how much is wrong.
//
// Both directions are asserted from one fixture certificate, so a fix that
// de-duplicated the reverse sweep by breaking the forward one fails here.
func TestCompareExtensionsCollapsesADuplicateOIDInBothDirections(t *testing.T) {
	t.Parallel()
	// A certificate genuinely carrying the same OID twice, with different values
	// so that the first-occurrence rule is observable in the reported Drift.
	dup := mustOID(t, "2.5.29.31") // cRLDistributionPoints, which no template here sets
	first := pkix.Extension{Id: dup, Value: []byte{0x04, 0x01, 0xaa}}
	second := pkix.Extension{Id: dup, Value: []byte{0x04, 0x01, 0xbb}}

	// Reverse direction: the template does not name the OID at all.
	reverse := compareExtensions(nil, []pkix.Extension{first, second})
	if len(reverse) != 1 {
		t.Fatalf("a duplicated OID absent from the template produced %d drift entries (%v), want 1", len(reverse), reverse)
	}
	if reverse[0].Field != "2.5.29.31" || reverse[0].Want != "absent" {
		t.Errorf("reverse drift = %v, want 2.5.29.31 wanting absent", reverse[0])
	}
	if want := describeExtension(first); reverse[0].Got != want {
		t.Errorf("reverse drift reported %q, want the first occurrence %q; the two sweeps disagree on which copy wins",
			reverse[0].Got, want)
	}

	// Forward direction: the template names the OID, and the certificate's first
	// occurrence is the one compared against it. Asserted alongside the reverse
	// case because "collapse duplicates" is only consistent if both sweeps pick
	// the same copy.
	forward := compareExtensions([]pkix.Extension{second}, []pkix.Extension{first, second})
	if len(forward) != 1 {
		t.Fatalf("a duplicated OID named by the template produced %d drift entries (%v), want 1", len(forward), forward)
	}
	if got, want := forward[0].Got, describeExtension(first); got != want {
		t.Errorf("forward drift reported %q, want the first occurrence %q", got, want)
	}

	// And the same certificate compared against a template that names the first
	// occurrence reports nothing, which is what proves the single entry above is a
	// real difference rather than the duplicate itself being reported.
	if clean := compareExtensions([]pkix.Extension{first}, []pkix.Extension{first, second}); len(clean) != 0 {
		t.Errorf("a duplicated OID matching the template on its first occurrence reported %v, want no drift", clean)
	}
}

// TestADuplicateExtensionOIDCannotBeParsed records why the collapse in
// compareExtensions is defensive rather than load-bearing, and is the reason this
// file tests the duplicate case on a constructed certificate rather than a parsed
// one.
//
// The finding this closes was written expecting "a certificate genuinely carrying
// a duplicate OID" to be producible and parseable. It is producible --
// x509.CreateCertificate writes whatever ExtraExtensions holds, RFC 5280 4.2
// notwithstanding -- and it is not parseable: crypto/x509's parser.go keeps a
// seenExts set and fails the whole certificate. Measured on go1.25.12.
//
// So a duplicate OID cannot reach CompareCertificate from a PEM file, a
// Kubernetes Secret, or Terraform state. It can only reach it from an
// x509.Certificate a caller assembled in code, which is what the test below does.
// Pinning the parser's behavior here means that if a future Go relaxes it -- and
// the check is a policy choice, not a structural necessity -- this test fails and
// points at the two sweeps that then start mattering for real input.
func TestADuplicateExtensionOIDCannotBeParsed(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "duplicate-oid-issuer")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	dup := mustOID(t, "2.5.29.31") // cRLDistributionPoints, which no template here sets
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "duplicate-oid-leaf"},
		NotBefore:    root.NotBefore,
		NotAfter:     root.NotAfter,
		ExtraExtensions: []pkix.Extension{
			{Id: dup, Value: []byte{0x04, 0x01, 0xaa}},
			{Id: dup, Value: []byte{0x04, 0x01, 0xbb}},
		},
	}, root, PublicKeyOf(key), rootKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate refused to write a duplicate extension, so this test proves nothing: %v", err)
	}

	_, err = x509.ParseCertificate(der)
	if err == nil {
		t.Fatal("x509.ParseCertificate accepted a certificate carrying a duplicate extension OID; compareExtensions' duplicate collapse is now reachable from real input and needs a test over parsed bytes")
	}
	if !strings.Contains(err.Error(), "duplicate extension") {
		t.Errorf("x509.ParseCertificate failed for some other reason than the duplicate, so this test is not pinning what it claims: %v", err)
	}
	// ParseCertificatePEM is the door real input comes through, and it must refuse
	// the same bytes.
	if _, err := ParseCertificatePEM(EncodeCertificatePEM(der)); err == nil {
		t.Error("ParseCertificatePEM accepted a certificate carrying a duplicate extension OID")
	}
}

// TestCompareCertificateCollapsesADuplicateOIDEndToEnd is the same property as
// TestCompareExtensionsCollapsesADuplicateOIDInBothDirections, through the
// exported entry point rather than the unexported helper, so the de-duplication is
// pinned at the boundary a caller actually uses.
//
// The duplicate is added to a parsed certificate's Extensions slice rather than to
// its DER, because TestADuplicateExtensionOIDCannotBeParsed establishes that DER
// carrying a duplicate does not parse. Everything else about the certificate --
// RawSubject, RawTBSCertificate, Signature -- is the real issued article, so the
// subject, serial, validity and signature checks all pass and the extension sweeps
// are the only thing that can report anything.
func TestCompareCertificateCollapsesADuplicateOIDEndToEnd(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	dup := mustOID(t, "2.5.29.31")

	actual := *leaf
	actual.Extensions = append(slices.Clone(leaf.Extensions),
		pkix.Extension{Id: dup, Value: []byte{0x04, 0x01, 0xaa}},
		pkix.Extension{Id: dup, Value: []byte{0x04, 0x01, 0xbb}},
	)

	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: &actual, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	// Exactly one entry for the duplicated OID, and nothing else at all: the rest
	// of the certificate matches its template, so any other entry means this test
	// is measuring something it did not intend to.
	if got := driftFields(drift); got != "2.5.29.31" {
		t.Fatalf("CompareCertificate reported drift %v (fields %q), want exactly one entry for 2.5.29.31", drift, got)
	}
	if drift[0].Want != "absent" {
		t.Errorf("drift = %v, want the reverse sweep's absent form", drift[0])
	}
	if want := describeExtension(pkix.Extension{Id: dup, Value: []byte{0x04, 0x01, 0xaa}}); drift[0].Got != want {
		t.Errorf("drift reported %q, want the first occurrence %q", drift[0].Got, want)
	}
}

// TestCompareCertificateReportsAnUnencodableSubjectAsAnError is the reason the
// comparison calls EncodeDER rather than Subject.Equal. A DN that parses but
// cannot be re-encoded -- here a PrintableString holding '@' -- must surface the
// cause, not present as permanent unexplained drift on every plan.
func TestCompareCertificateReportsAnUnencodableSubjectAsAnError(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)
	desired.Subject = Subject{Attributes: []Attribute{{
		OID:        mustDNOID(t, "commonName"),
		Value:      "nick@venenga.com",
		StringType: StringTypePrintable,
	}}}
	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
	})
	if err == nil {
		t.Fatalf("an unencodable desired subject returned drift %v and a nil error, want an error", drift)
	}
	if len(drift) != 0 {
		t.Errorf("drift = %v, want no drift alongside the error", drift)
	}
	if !strings.Contains(err.Error(), "PrintableString") {
		t.Errorf("err = %v, want it to name the encoding that failed", err)
	}
}

func TestDriftString(t *testing.T) {
	t.Parallel()
	// Drift strings end up in a Terraform plan explanation, so they must name
	// the field and both sides.
	got := Drift{Field: "serial_number", Want: "2001", Got: "2002"}.String()
	for _, want := range []string{"serial_number", "2001", "2002"} {
		if !strings.Contains(got, want) {
			t.Errorf("Drift.String() = %q, want it to contain %q", got, want)
		}
	}
}

// TestExtensionValuesAreRenderedAsTruncatedHex pins the readability cap on
// extension values in a drift report. A nameConstraints or SAN value runs to
// hundreds of bytes, and a plan explanation carrying a thousand hex characters
// hides the line the operator needs.
func TestExtensionValuesAreRenderedAsTruncatedHex(t *testing.T) {
	t.Parallel()
	if got := describeExtension(pkix.Extension{Value: []byte{0x05, 0x00}}); got != "0500" {
		t.Errorf("describeExtension of a short value = %q, want %q", got, "0500")
	}
	if got := describeExtension(pkix.Extension{Value: []byte{0x05, 0x00}, Critical: true}); got != "critical 0500" {
		t.Errorf("describeExtension of a critical value = %q, want %q", got, "critical 0500")
	}
	long := describeExtension(pkix.Extension{Value: bytes.Repeat([]byte{0xab}, 100)})
	if len(long) != maxDriftValueHexChars+len("...") || !strings.HasSuffix(long, "...") {
		t.Errorf("describeExtension of a 100-byte value = %q (%d chars), want %d hex chars and an ellipsis",
			long, len(long), maxDriftValueHexChars)
	}
}

func TestCompareValidity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	leaf, _, _ := testLeaf(t)
	cert := *leaf
	cert.NotBefore = now.Add(-24 * time.Hour)
	cert.NotAfter = now.Add(48 * time.Hour)

	for label, tc := range map[string]struct {
		earlyRenewal time.Duration
		want         bool
	}{
		"no early renewal":         {0, false},
		"outside the window":       {24 * time.Hour, false},
		"exactly at the boundary":  {48 * time.Hour, true},
		"inside the window":        {72 * time.Hour, true},
		"longer than the lifetime": {365 * 24 * time.Hour, true},
	} {
		got, err := CompareValidity(&cert, tc.earlyRenewal, now)
		if err != nil {
			t.Errorf("%s: CompareValidity: %v", label, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: CompareValidity = %v, want %v", label, got, tc.want)
		}
	}

	// An already-expired certificate is ready for renewal regardless.
	expired := cert
	expired.NotAfter = now.Add(-time.Hour)
	if ready, err := CompareValidity(&expired, 0, now); err != nil {
		t.Errorf("CompareValidity(expired): %v", err)
	} else if !ready {
		t.Error("an expired certificate is not reported ready for renewal")
	}
}

// TestCompareValidityRejectsANilCertificate pins the nil contract this function
// used to have no answer to at all: it dereferenced actual.NotAfter and panicked,
// while its signature advertised a pointer and documented nothing about nil.
//
// An error rather than a bool is what the rest of compare.go does with a
// precondition -- CompareCertificate has four of them -- and both bool answers
// would be worse than a panic rather than better. A nil certificate reported as
// ready for renewal makes the provider reissue on the strength of a certificate it
// never looked at, which for a 20-year certificate installed on a phone means a
// manual re-enrollment; reported as not ready, a resource silently stops renewing
// and the operator finds out when TLS starts failing. The false alongside the
// error is deliberate and asserted: a caller that ignores the error must not get
// the reissuing answer.
func TestCompareValidityRejectsANilCertificate(t *testing.T) {
	t.Parallel()
	ready, err := CompareValidity(nil, 24*time.Hour, time.Now())
	if err == nil {
		t.Fatalf("CompareValidity(nil) returned %v and a nil error, want an error", ready)
	}
	if ready {
		t.Error("CompareValidity(nil) returned true alongside its error; a caller dropping the error would reissue")
	}
	if !strings.Contains(err.Error(), "actual certificate is required") {
		t.Errorf("err = %v, want it to name the missing input", err)
	}
}
