// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
// asserts no drift, so the nil-CA branch could be a no-op and it would still be
// green. A CA-signed leaf compared with no CA is not self-signed, and the
// self-signature check has to say so.
func TestCompareCertificateNilCAOnACASignedCertificateIsDrift(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 1 || drift[0].Field != "signature" {
		t.Fatalf("drift = %v, want exactly one entry for \"signature\"", drift)
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
		if got := CompareValidity(&cert, tc.earlyRenewal, now); got != tc.want {
			t.Errorf("%s: CompareValidity = %v, want %v", label, got, tc.want)
		}
	}

	// An already-expired certificate is ready for renewal regardless.
	expired := cert
	expired.NotAfter = now.Add(-time.Hour)
	if !CompareValidity(&expired, 0, now) {
		t.Error("an expired certificate is not reported ready for renewal")
	}
}
