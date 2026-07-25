// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// mustDNOID looks up a DN attribute OID or fails the test. It exists so table
// literals can stay expressions.
func mustDNOID(t *testing.T, name string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := DNAttributeOID(name)
	if err != nil {
		t.Fatalf("DNAttributeOID(%q): %v", name, err)
	}
	return oid
}

// mustOID parses a dotted OID or fails the test.
func mustOID(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := ParseOID(s)
	if err != nil {
		t.Fatalf("ParseOID(%q): %v", s, err)
	}
	return oid
}

// requireOpenSSL returns the path to the openssl binary, skipping the test when
// it is not installed. Cross-validation against a real parser is valuable but
// must never be the reason a contributor's test run fails.
func requireOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH; skipping cross-validation")
	}
	return path
}

// testCA issues a CA certificate and returns it with its key. With a nil parent
// it self-signs a root; otherwise it issues an intermediate under the parent.
// The key is ECDSA P-256 because these fixtures are created in almost every
// test and RSA generation dominates the suite's runtime otherwise.
func testCA(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signerKey := key
	if parentKey != nil {
		signerKey = parentKey
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
	}, PublicKeyOf(key), parent, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(%s): %v", cn, err)
	}
	return cert, key
}

// opensslText runs `openssl x509 -text -noout` over a PEM certificate and
// returns its output, so tests can assert that a real parser agrees with what
// this package produced.
//
// -nameopt oneline is passed explicitly rather than relying on the default,
// because the default is not stable across builds: OpenSSL 3.5.7 renders a DN as
// "CN=homelab, UID=nick" while oneline renders it as "CN = homelab, UID = nick",
// and a test that hardcodes either form without pinning the flag fails on the
// other. oneline is the spaced form, which is what openssl documents as its
// name-printing default and what the assertions here are written against.
func opensslText(t *testing.T, certPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "x509", "-noout", "-text", "-nameopt", "oneline")
	cmd.Stdin = bytes.NewReader(certPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	return string(out)
}

// opensslCRLText runs `openssl crl -text -noout` over a PEM CRL.
func opensslCRLText(t *testing.T, crlPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "crl", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(crlPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl -text failed: %v\n%s", err, out)
	}
	return string(out)
}

// testLeaf issues a leaf certificate under a fresh CA and returns the leaf, the
// leaf's key, and the CA certificate.
func testLeaf(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "nick-ipad.ha.apps.somemissing.info"}.Expand(),
		SAN:              SAN{DNSNames: []string{"nick-ipad.ha.apps.somemissing.info"}, EmailAddresses: []string{"nick@venenga.com"}},
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return leaf, key, ca
}

// opensslRun pipes input to openssl with the given arguments and returns
// combined output, failing the test if openssl exits non-zero.
func opensslRun(t *testing.T, input []byte, args ...string) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
