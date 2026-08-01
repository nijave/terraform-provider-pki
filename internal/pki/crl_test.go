// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCreateCRLRoundTripAndSignature(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")

	thisUpdate := time.Now().Truncate(time.Second).UTC()
	tmpl := CRLTemplate{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(168 * time.Hour),
		Revoked: []RevokedCert{
			{Serial: big.NewInt(0x2001), Reason: "keyCompromise", RevokedAt: thisUpdate.Add(-24 * time.Hour)},
			{Serial: big.NewInt(0x2002), RevokedAt: thisUpdate.Add(-time.Hour)},
		},
	}
	crlPEM, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := ParseCRLPEM(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}

	// Spec section 10: the CRL signature verifies against the CA and a revoked
	// serial is present.
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("CRL signature does not verify against the issuing CA: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("CRL number = %s, want 1", crl.Number)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL has %d entries, want 2", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(0x2001)) != 0 {
		t.Errorf("entry 0 serial = %s, want 8193 (0x2001)", crl.RevokedCertificateEntries[0].SerialNumber)
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("entry 0 reason code = %d, want 1 (keyCompromise)", crl.RevokedCertificateEntries[0].ReasonCode)
	}
	// An omitted reason must not become "unspecified with an explicit code": RFC
	// 5280 says omit the extension entirely, and code 0 is how Go signals that.
	if crl.RevokedCertificateEntries[1].ReasonCode != 0 {
		t.Errorf("entry 1 reason code = %d, want 0 (no reasonCode extension)", crl.RevokedCertificateEntries[1].ReasonCode)
	}
	if !crl.ThisUpdate.Equal(thisUpdate) {
		t.Errorf("thisUpdate = %s, want %s", crl.ThisUpdate, thisUpdate)
	}
}

func TestCreateCRLWithNoRevocations(t *testing.T) {
	t.Parallel()
	// An empty CRL is the normal steady state: config.hcl ships
	// revoked_serials = [] and the cluster still needs a fresh, valid CRL for
	// Envoy to load.
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL with no revocations: %v", err)
	}
	crl, err := ParseCRLPEM(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("empty CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("empty CRL signature does not verify: %v", err)
	}
}

func TestCreateCRLPEMBlockType(t *testing.T) {
	t.Parallel()
	// engine.py converted cfssl's DER output to PEM specifically so downstream
	// consumers (Envoy, HTTPProxy) get a standard file. The block type is what
	// they key on.
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	if !strings.HasPrefix(string(crlPEM), "-----BEGIN X509 CRL-----") {
		t.Fatalf("CRL PEM starts with %q, want \"-----BEGIN X509 CRL-----\"", string(crlPEM[:30]))
	}
}

// TestCheckCRLSignerRejectsACAWithoutCRLSign is the guard on the migration
// hazard: cfssl signed CRLs with any CA key, but Go requires the issuer to
// carry keyUsage crlSign and a subjectKeyIdentifier. The externally-owned
// Bitwarden CA cannot be inspected ahead of time, so the error must say exactly
// what is wrong and what to do.
func TestCheckCRLSignerRejectsACAWithoutCRLSign(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// A CA whose keyUsage omits crlSign.
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "no-crlsign-ca"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign"}, Critical: true},
	}, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	ca, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	err = CheckCRLSigner(ca)
	if err == nil {
		t.Fatal("CheckCRLSigner accepted a CA without crlSign")
	}
	if !strings.Contains(err.Error(), "crlSign") {
		t.Errorf("error message %q does not mention crlSign; a caller cannot act on it", err.Error())
	}

	now := time.Now()
	if _, err := CreateCRL(CRLTemplate{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, ca, key); err == nil {
		t.Fatal("CreateCRL signed with a CA that lacks crlSign")
	}
}

func TestCreateCRLRejectsBadTemplates(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	base := func() CRLTemplate {
		return CRLTemplate{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(168 * time.Hour)}
	}
	for label, mutate := range map[string]func(CRLTemplate) CRLTemplate{
		"nil number":      func(c CRLTemplate) CRLTemplate { c.Number = nil; return c },
		"negative number": func(c CRLTemplate) CRLTemplate { c.Number = big.NewInt(-1); return c },
		// RFC 5280 5.2.3: CRLNumber is an INTEGER that must fit in 20 octets
		// (160 bits). The brief calls out validating this explicitly rather
		// than letting Go's own error surface, but named no test case for it;
		// added here to close that hole.
		"number exceeds 160 bits": func(c CRLTemplate) CRLTemplate {
			c.Number = new(big.Int).Lsh(big.NewInt(1), 161)
			return c
		},
		"zero thisUpdate": func(c CRLTemplate) CRLTemplate { c.ThisUpdate = time.Time{}; return c },
		"zero nextUpdate": func(c CRLTemplate) CRLTemplate { c.NextUpdate = time.Time{}; return c },
		"nextUpdate before": func(c CRLTemplate) CRLTemplate {
			c.NextUpdate = c.ThisUpdate.Add(-time.Hour)
			return c
		},
		"nil entry serial": func(c CRLTemplate) CRLTemplate { c.Revoked = []RevokedCert{{RevokedAt: now}}; return c },
		"zero revokedAt":   func(c CRLTemplate) CRLTemplate { c.Revoked = []RevokedCert{{Serial: big.NewInt(1)}}; return c },
		"unknown reason": func(c CRLTemplate) CRLTemplate {
			c.Revoked = []RevokedCert{{Serial: big.NewInt(1), RevokedAt: now, Reason: "becauseIFeltLikeIt"}}
			return c
		},
		"duplicate serial": func(c CRLTemplate) CRLTemplate {
			c.Revoked = []RevokedCert{{Serial: big.NewInt(1), RevokedAt: now}, {Serial: big.NewInt(1), RevokedAt: now}}
			return c
		},
	} {
		if _, err := CreateCRL(mutate(base()), ca, caKey); err == nil {
			t.Errorf("CreateCRL(%s) returned nil error, want an error", label)
		}
	}

	// This value sits exactly on the boundary a naive `Number.BitLen() > 160`
	// check would miss: BitLen() == 160, but the top byte's high bit is set,
	// so the DER INTEGER encoding still needs a 21st sign-padding byte and
	// therefore still exceeds the 20-octet limit RFC 5280 5.2.3 places on
	// CRLNumber. It must be rejected by this package's own validation, with a
	// message naming the limit -- not fall through to
	// x509.CreateRevocationList's own opaque "x509: CRL number exceeds 20
	// octets".
	boundary := base()
	boundary.Number = new(big.Int).Lsh(big.NewInt(1), 159)
	_, err := CreateCRL(boundary, ca, caKey)
	if err == nil {
		t.Fatal("CreateCRL accepted a CRL number whose DER encoding needs 21 octets")
	}
	if !strings.Contains(err.Error(), "20-octet") {
		t.Errorf("boundary CRL number error = %q, want it to name the 20-octet limit", err.Error())
	}
}

// TestCreateCRLRejectsAnInsecureSignatureAlgorithm is the CRL-side twin of
// TestCreateCertificateRejectsInsecureSignatureAlgorithms.
//
// CreateCRL used to hand-roll only the defaulting half of what
// resolveSignatureAlgorithm does, so the allow-list that keeps SHA-1 and MD5 out
// of certificates did not cover CRLs at all: this call produced a SHA-1 signed
// CRL without complaint, while the equivalent CreateCertificate call was refused
// by name. The signing key here is the family SHA1WithRSA requires, so nothing
// but the allow-list can reject it.
func TestCreateCRLRejectsAnInsecureSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	rsaCA, rsaCAKey := testRSACA(t, "rsa-ca")
	now := time.Now().Truncate(time.Second).UTC()
	_, err := CreateCRL(CRLTemplate{
		Number:             big.NewInt(1),
		ThisUpdate:         now,
		NextUpdate:         now.Add(168 * time.Hour),
		SignatureAlgorithm: x509.SHA1WithRSA,
	}, rsaCA, rsaCAKey)
	if err == nil {
		t.Fatal("CreateCRL accepted SHA1WithRSA, which this package does not offer")
	}
	if !strings.Contains(err.Error(), "not offered") {
		t.Errorf("error = %q, want it to report that the algorithm is not offered", err)
	}
}

// TestCreateCRLMismatchedSignatureAlgorithmNamesTheKeyFamily pins that a family
// mismatch on the CRL path is reported by this package's own message, naming the
// algorithm and both key families, rather than by crypto/x509's "requested
// SignatureAlgorithm does not match private key type" -- which names neither the
// attribute the operator wrote nor the key they supplied, and is exactly what
// signatureAlgorithmKeyTypes exists to replace.
func TestCreateCRLMismatchedSignatureAlgorithmNamesTheKeyFamily(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca") // ECDSA P-256
	now := time.Now().Truncate(time.Second).UTC()
	_, err := CreateCRL(CRLTemplate{
		Number:             big.NewInt(1),
		ThisUpdate:         now,
		NextUpdate:         now.Add(168 * time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, ca, caKey)
	if err == nil {
		t.Fatal("CreateCRL accepted an RSA signature algorithm with an ECDSA signing key")
	}
	if !strings.Contains(err.Error(), "requires a RSA signing key") {
		t.Errorf("error = %q, want this package's message naming the required key family", err)
	}
	if strings.Contains(err.Error(), "does not match private key type") {
		t.Errorf("error = %q, want this package's message rather than crypto/x509's", err)
	}
}

func TestReasonCodes(t *testing.T) {
	t.Parallel()
	// RFC 5280 5.3.1. Note that 7 is unused and must not be accepted.
	for name, want := range map[string]int{
		"unspecified":          0,
		"keyCompromise":        1,
		"cACompromise":         2,
		"affiliationChanged":   3,
		"superseded":           4,
		"cessationOfOperation": 5,
		"certificateHold":      6,
		"removeFromCRL":        8,
		"privilegeWithdrawn":   9,
		"aACompromise":         10,
	} {
		got, err := ReasonCode(name)
		if err != nil {
			t.Errorf("ReasonCode(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ReasonCode(%q) = %d, want %d", name, got, want)
		}
		back, err := ReasonName(want)
		if err != nil || back != name {
			t.Errorf("ReasonName(%d) = %q, %v; want %q, nil", want, back, err, name)
		}
	}
	if _, err := ReasonCode("keycompromise"); err == nil {
		t.Error("ReasonCode is case-insensitive; the schema's values are the RFC's exact spellings")
	}
	if _, err := ReasonName(7); err == nil {
		t.Error("ReasonName(7) succeeded; 7 is unused in RFC 5280")
	}
	// ReasonNames' order is part of its contract, not an accident of
	// implementation: it sorts by numeric code so generated documentation and
	// every error message that interpolates it read in the order RFC 5280 5.3.1
	// lists the reasons. A count alone would not notice an accidental switch to
	// the alphabetical order sort.Strings would give -- which starts
	// "aACompromise, affiliationChanged, cACompromise" rather than "unspecified,
	// keyCompromise, cACompromise" -- so the sequence is pinned here.
	//
	// Note that code 7 is absent, which is why this is a list rather than a range:
	// removeFromCRL (8) follows certificateHold (6).
	wantOrder := []string{
		"unspecified",          // 0
		"keyCompromise",        // 1
		"cACompromise",         // 2
		"affiliationChanged",   // 3
		"superseded",           // 4
		"cessationOfOperation", // 5
		"certificateHold",      // 6
		"removeFromCRL",        // 8
		"privilegeWithdrawn",   // 9
		"aACompromise",         // 10
	}
	names := ReasonNames()
	if !slices.Equal(names, wantOrder) {
		t.Errorf("ReasonNames() = %v,\n                want %v", names, wantOrder)
	}
	// And the order really is the numeric one, checked against the table rather
	// than against the list above, so a name added to reasonCodes without being
	// added there cannot pass by matching a stale expectation.
	for i := 1; i < len(names); i++ {
		if reasonCodes[names[i-1]] >= reasonCodes[names[i]] {
			t.Errorf("ReasonNames() is not sorted by code: %q (%d) precedes %q (%d)",
				names[i-1], reasonCodes[names[i-1]], names[i], reasonCodes[names[i]])
		}
	}
	if len(names) != len(reasonCodes) {
		t.Errorf("ReasonNames returned %d names, but reasonCodes has %d entries", len(names), len(reasonCodes))
	}
}

// TestCreateCRLIsDeterministicForTheSameTemplate keeps regeneration from
// producing gratuitously different bytes, which would churn the Kubernetes
// Secret on every apply even when nothing changed.
func TestCreateCRLIsDeterministicForTheSameTemplate(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	tmpl := CRLTemplate{
		Number:     big.NewInt(7),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
		Revoked:    []RevokedCert{{Serial: big.NewInt(0x2001), RevokedAt: now.Add(-time.Hour)}},
	}
	a, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	b, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	// ECDSA signatures are randomized, so the signature bytes differ by design.
	// The signed content must not.
	first, err := ParseCRLPEM(a)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	second, err := ParseCRLPEM(b)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	if string(first.RawTBSRevocationList) != string(second.RawTBSRevocationList) {
		t.Fatal("the same template produced different signed content across two calls")
	}
}

func TestParseCRLPEMRejectsGarbage(t *testing.T) {
	t.Parallel()
	for label, in := range map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("hello"),
		"wrong block": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	} {
		if _, err := ParseCRLPEM(in); err == nil {
			t.Errorf("ParseCRLPEM(%s) returned nil error, want an error", label)
		}
	}
}

func TestCRLIsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number:     big.NewInt(3),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
		Revoked:    []RevokedCert{{Serial: big.NewInt(0x2001), Reason: "keyCompromise", RevokedAt: now.Add(-time.Hour)}},
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	text := opensslCRLText(t, crlPEM)
	for _, want := range []string{"Serial Number: 2001", "Key Compromise"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl crl output does not contain %q:\n%s", want, text)
		}
	}
	// Deviation from the brief: it asserted strings.Contains(text, "CRL Number:
	// 3"), but openssl 3.5.7 (the version this task's notes say is installed,
	// and what is actually on PATH here) prints the CRL Number extension's name
	// and value on separate lines:
	//
	//	X509v3 CRL Number:
	//	    3
	//
	// so that literal substring can never appear and the assertion as written
	// is impossible to satisfy. This regexp keeps the same intent -- the CRL
	// Number extension carries value 3 -- while tolerating the line break.
	if !regexp.MustCompile(`CRL Number:\s*3\b`).MatchString(text) {
		t.Errorf("openssl crl output does not show CRL Number 3:\n%s", text)
	}
	_ = x509.RevocationList{} // keep the x509 import honest if assertions change
}
